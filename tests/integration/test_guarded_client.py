"""Integration tests for the bulkhead, and for the assembled resilience stack.

The unit tests cover the breaker's state machine in isolation. What is worth
testing here is the composition, because the ordering of the layers is a
correctness property rather than a stylistic one: retry must count as separate
attempts to the breaker, an open circuit must not be retried, and a bulkhead
rejection must not be mistaken for the upstream being unhealthy.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import (
    UpstreamCircuitOpenError,
    UpstreamOverloadedError,
    UpstreamTimeoutError,
)
from acp.upstream import UpstreamClient, UpstreamConfig, build_upstream
from acp.upstream.breaker import BreakerPolicy, BreakerState, CircuitBreaker
from acp.upstream.guard import Bulkhead, GuardedUpstreamClient
from acp.upstream.resilient import RetryingUpstreamClient, policy_for


class CountingBreaker(CircuitBreaker):
    """Counts how many times a caller reached the gate, admitted or refused.

    The observable that matters for the retry tests: a rejected call leaves no
    trace on the transport, so counting requests cannot tell a single fast
    failure apart from five retries of one.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.entries = 0

    @asynccontextmanager
    async def guard(self) -> AsyncIterator[None]:
        self.entries += 1
        async with super().guard():
            yield


class CountingBulkhead(Bulkhead):
    """Counts slot requests, for the same reason."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.requests = 0

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        self.requests += 1
        async with super().slot():
            yield


pytestmark = pytest.mark.integration


class CountingTransport(httpx.AsyncBaseTransport):
    """Counts requests and replays a scripted outcome, holding if asked to."""

    def __init__(
        self, outcome: httpx.Response | Exception, *, hold: anyio.Event | None = None
    ) -> None:
        self.outcome = outcome
        self.hold = hold
        self.count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.count += 1
        if self.hold is not None:
            await self.hold.wait()
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def ok_tools() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "search", "inputSchema": {"type": "object"}}]},
        },
    )


def a_timeout() -> httpx.ReadTimeout:
    return httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://mock/mcp"))


def config(**overrides: Any) -> UpstreamConfig:
    defaults: dict[str, Any] = {
        "name": "mock-a",
        "url": "http://mock/mcp",
        "initial_backoff": 0.001,
        "max_backoff": 0.001,
    }
    return UpstreamConfig(**{**defaults, **overrides})


def guarded(transport: CountingTransport, cfg: UpstreamConfig) -> GuardedUpstreamClient:
    inner = UpstreamClient(cfg, httpx.AsyncClient(transport=transport))
    return GuardedUpstreamClient(
        inner,
        CircuitBreaker(
            cfg.name,
            BreakerPolicy(
                failure_threshold=cfg.failure_threshold,
                reset_timeout=cfg.reset_timeout,
                half_open_max_calls=cfg.half_open_max_calls,
            ),
        ),
        Bulkhead(cfg.name, cfg.max_concurrency),
    )


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# The bulkhead
# ---------------------------------------------------------------------------


def test_calls_beyond_capacity_are_refused_rather_than_queued() -> None:
    """The refusal is the feature.

    Queueing would turn saturation into latency, and latency is exactly what a
    caller cannot tell apart from the upstream being slow. Refusing says
    something true, immediately.
    """
    hold = anyio.Event()
    transport = CountingTransport(ok_tools(), hold=hold)
    cfg = config(max_concurrency=2, max_connections=10)
    refused = 0

    async def _run() -> None:
        nonlocal refused
        async with guarded(transport, cfg) as client:

            async def caller() -> None:
                nonlocal refused
                try:
                    await client.list_tools()
                except UpstreamOverloadedError:
                    refused += 1

            async with anyio.create_task_group() as tg:
                for _ in range(5):
                    tg.start_soon(caller)
                await anyio.sleep(0.05)
                hold.set()

    run(_run)

    assert refused == 3
    assert transport.count == 2, "the refused calls must never reach the network"


def test_slots_are_returned_when_a_call_finishes() -> None:
    transport = CountingTransport(ok_tools())
    cfg = config(max_concurrency=1, max_connections=10)

    async def _run() -> int:
        async with guarded(transport, cfg) as client:
            for _ in range(4):
                await client.list_tools()
            return client.bulkhead.in_flight

    assert run(_run) == 0
    assert transport.count == 4


def test_a_slot_is_returned_even_when_the_call_fails() -> None:
    """A leaked slot is permanent — capacity only ever goes down — so this is
    the one bulkhead bug that degrades into a total outage."""
    transport = CountingTransport(a_timeout())
    cfg = config(max_concurrency=1, max_connections=10, failure_threshold=100)

    async def _run() -> int:
        async with guarded(transport, cfg) as client:
            for _ in range(3):
                with pytest.raises(UpstreamTimeoutError):
                    await client.list_tools()
            return client.bulkhead.in_flight

    assert run(_run) == 0


def test_overload_does_not_count_against_the_upstreams_health() -> None:
    """Being busy is the gateway's condition, not the upstream's.

    If saturation opened circuits, a burst of traffic against a perfectly
    healthy upstream would take it out of the catalogue.
    """
    hold = anyio.Event()
    transport = CountingTransport(ok_tools(), hold=hold)
    cfg = config(max_concurrency=1, max_connections=10, failure_threshold=2)

    async def _run() -> BreakerState:
        async with guarded(transport, cfg) as client:

            async def caller() -> None:
                with contextlib.suppress(UpstreamOverloadedError):
                    await client.list_tools()

            async with anyio.create_task_group() as tg:
                for _ in range(6):
                    tg.start_soon(caller)
                await anyio.sleep(0.05)
                hold.set()
            return client.breaker.state

    assert run(_run) is BreakerState.CLOSED


def test_an_open_circuit_does_not_wait_for_bulkhead_capacity() -> None:
    """Ordering: the breaker is checked before a slot is taken.

    The cheapest possible answer — "this upstream is down" — should not queue
    behind the most expensive one. Tested by exhausting the bulkhead by hand
    and asserting the call still comes back as an open circuit rather than as
    overload, which is only true if the breaker is consulted first.
    """
    transport = CountingTransport(a_timeout())
    cfg = config(max_concurrency=1, max_connections=10, failure_threshold=1)
    bulkhead = Bulkhead(cfg.name, cfg.max_concurrency)
    inner = UpstreamClient(cfg, httpx.AsyncClient(transport=transport))
    client = GuardedUpstreamClient(
        inner, CircuitBreaker(cfg.name, BreakerPolicy(failure_threshold=1)), bulkhead
    )

    async def _run() -> None:
        async with client:
            with pytest.raises(UpstreamTimeoutError):
                await client.list_tools()  # opens the circuit

            async with bulkhead.slot():  # the only slot is now taken
                assert bulkhead.in_flight == 1
                with anyio.fail_after(1.0):
                    with pytest.raises(UpstreamCircuitOpenError):
                        await client.list_tools()

    run(_run)


# ---------------------------------------------------------------------------
# The breaker, through a real client
# ---------------------------------------------------------------------------


def test_repeated_timeouts_open_the_circuit_and_stop_the_traffic() -> None:
    transport = CountingTransport(a_timeout())
    cfg = config(failure_threshold=3, max_concurrency=10, max_connections=10)

    async def _run() -> None:
        async with guarded(transport, cfg) as client:
            for _ in range(3):
                with pytest.raises(UpstreamTimeoutError):
                    await client.list_tools()
            for _ in range(20):
                with pytest.raises(UpstreamCircuitOpenError):
                    await client.list_tools()

    run(_run)

    assert transport.count == 3, (
        "23 calls, 3 requests: the whole point is that a dead upstream stops "
        "costing a timeout per caller"
    )


# ---------------------------------------------------------------------------
# The assembled stack
# ---------------------------------------------------------------------------


def stack(transport: CountingTransport, cfg: UpstreamConfig) -> Any:
    return build_upstream(UpstreamClient(cfg, httpx.AsyncClient(transport=transport)))


def test_retries_are_counted_individually_by_the_breaker() -> None:
    """Why retry sits *outside* the breaker.

    Three failed attempts are three pieces of evidence that the upstream is
    down. If the breaker only saw completed calls it would need three times as
    many failures to open, and the whole point is to stop wasting time sooner.
    """
    transport = CountingTransport(a_timeout())
    cfg = config(max_attempts=3, failure_threshold=3, max_concurrency=10, max_connections=10)

    async def _run() -> None:
        async with stack(transport, cfg) as client:
            with pytest.raises(UpstreamTimeoutError):
                await client.list_tools()  # 3 attempts, 3 failures, circuit opens
            with pytest.raises(UpstreamCircuitOpenError):
                await client.list_tools()

    run(_run)

    assert transport.count == 3


def test_an_open_circuit_ends_the_retry_loop_immediately() -> None:
    """`retry_locally` in action, and a case worth being precise about.

    With a threshold of one, a single call can open the circuit and then be
    refused by it on its own second attempt. The refusal is what surfaces, not
    the timeout underneath — which is the better of the two for an agent to
    receive, because it carries ``retry_after_seconds`` and the timeout does
    not.

    What must not happen is the retry loop grinding through all five attempts
    against a gate that cannot move in milliseconds. Gate entries are the
    observable: a refused call never reaches the transport, so counting
    requests would leave five retries looking exactly like one.
    """
    transport = CountingTransport(a_timeout())
    cfg = config(max_attempts=5, failure_threshold=1, max_concurrency=10, max_connections=10)
    breaker = CountingBreaker(cfg.name, BreakerPolicy(failure_threshold=1))
    inner = UpstreamClient(cfg, httpx.AsyncClient(transport=transport))
    client = RetryingUpstreamClient(
        GuardedUpstreamClient(inner, breaker, Bulkhead(cfg.name, cfg.max_concurrency)),
        policy_for(cfg),
    )

    async def _run() -> None:
        async with client:
            with pytest.raises(UpstreamCircuitOpenError):
                await client.list_tools()

            assert breaker.entries == 2, (
                "attempt 1 was admitted and failed, attempt 2 was refused, and "
                "the refusal ended the loop — five attempts were allowed"
            )
            assert transport.count == 1

            with pytest.raises(UpstreamCircuitOpenError):
                await client.list_tools()

            assert breaker.entries == 3, "a later call fails fast in one entry too"
            assert transport.count == 1

    run(_run)


def test_a_bulkhead_rejection_is_not_retried_either() -> None:
    """Retrying into a saturated upstream adds load to the thing that is
    already overloaded — and, like an open circuit, leaves no trace on the
    transport, so the slot requests are what has to be counted."""
    hold = anyio.Event()
    transport = CountingTransport(ok_tools(), hold=hold)
    cfg = config(max_attempts=5, max_concurrency=1, max_connections=10)
    bulkhead = CountingBulkhead(cfg.name, cfg.max_concurrency)
    inner = UpstreamClient(cfg, httpx.AsyncClient(transport=transport))
    client = RetryingUpstreamClient(
        GuardedUpstreamClient(inner, CircuitBreaker(cfg.name), bulkhead), policy_for(cfg)
    )

    async def _run() -> None:
        async with client:

            async def occupy() -> None:
                await client.list_tools()

            async def rejected() -> None:
                with pytest.raises(UpstreamOverloadedError):
                    await client.list_tools()

            async with anyio.create_task_group() as tg:
                tg.start_soon(occupy)
                await anyio.sleep(0.01)
                tg.start_soon(rejected)
                await anyio.sleep(0.05)
                hold.set()

    run(_run)

    assert bulkhead.requests == 2, (
        "one slot taken by the occupying call and one refusal — a retry would "
        "have queued four more refusals into an upstream already at capacity"
    )


def test_the_stack_still_looks_like_a_plain_upstream() -> None:
    """Everything above this layer — the registry, the server — holds an
    `Upstream` and must not be able to tell which wrappers are present."""
    transport = CountingTransport(ok_tools())
    cfg = config(max_concurrency=5, max_connections=10)

    async def _run() -> tuple[str, list[str]]:
        async with stack(transport, cfg) as client:
            return client.config.name, [t.name for t in (await client.list_tools()).tools]

    assert run(_run) == ("mock-a", ["search"])


# ---------------------------------------------------------------------------
# Tool calls take the same route
# ---------------------------------------------------------------------------


def ok_call(text: str = "done") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": text}], "isError": False},
        },
    )


def test_a_tool_call_passes_through_the_guard() -> None:
    transport = CountingTransport(ok_call("found it"))
    cfg = config(max_concurrency=2, max_connections=10)

    async def _run() -> tuple[str, int]:
        async with guarded(transport, cfg) as client:
            result = await client.call_tool("search", {"query": "x"})
            return result.text(), client.bulkhead.in_flight

    assert run(_run) == ("found it", 0), "the slot must be returned after the call"


def test_an_open_circuit_refuses_tool_calls_too() -> None:
    """The breaker protects the expensive path as well as the cheap one.

    Worth asserting separately: `list_tools` and `call_tool` reach the guard by
    different routes, and a wrapper that guards only the catalogue would look
    entirely healthy in a `tools/list` test while leaving every actual tool call
    unprotected.
    """
    transport = CountingTransport(a_timeout())
    cfg = config(max_concurrency=2, max_connections=10, failure_threshold=1)

    async def _run() -> None:
        async with guarded(transport, cfg) as client:
            with pytest.raises(UpstreamTimeoutError):
                await client.call_tool("search", {})
            for _ in range(5):
                with pytest.raises(UpstreamCircuitOpenError):
                    await client.call_tool("search", {})

    run(_run)

    assert transport.count == 1


def test_a_tool_call_is_refused_when_the_bulkhead_is_full() -> None:
    hold = anyio.Event()
    transport = CountingTransport(ok_call(), hold=hold)
    cfg = config(max_concurrency=1, max_connections=10)
    refused = 0

    async def _run() -> None:
        nonlocal refused
        async with guarded(transport, cfg) as client:

            async def caller() -> None:
                nonlocal refused
                try:
                    await client.call_tool("search", {})
                except UpstreamOverloadedError:
                    refused += 1

            async with anyio.create_task_group() as tg:
                for _ in range(3):
                    tg.start_soon(caller)
                await anyio.sleep(0.05)
                hold.set()

    run(_run)

    assert refused == 2
    assert transport.count == 1
