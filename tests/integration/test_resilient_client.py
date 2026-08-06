"""Integration tests for the retrying client, against real failure modes.

The interesting assertions here are the *negative* ones: that a non-idempotent
tool is not retried, and that an unrecoverable failure is not retried. Those are
the cases where retrying is actively harmful, and they are easy to get wrong by
being helpful.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import UpstreamProtocolError, UpstreamTimeoutError, UpstreamUnavailableError
from acp.upstream import UpstreamClient, UpstreamConfig
from acp.upstream.resilient import RetryingUpstreamClient, policy_for

pytestmark = pytest.mark.integration


class CountingTransport(httpx.AsyncBaseTransport):
    """Counts requests and replays a scripted sequence of outcomes."""

    def __init__(self, *outcomes: httpx.Response | Exception) -> None:
        self.outcomes: list[httpx.Response | Exception] = list(outcomes)
        self.count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        outcome = self.outcomes[min(self.count, len(self.outcomes) - 1)]
        self.count += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def ok_tools() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "search", "inputSchema": {"type": "object"}}]},
        },
    )


def ok_call(text: str = "done") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": text}], "isError": False},
        },
    )


def client(transport: CountingTransport, **config: Any) -> RetryingUpstreamClient:
    cfg = UpstreamConfig(
        name="mock-a", url="http://mock/mcp", initial_backoff=0.001, max_backoff=0.001, **config
    )
    inner = UpstreamClient(cfg, httpx.AsyncClient(transport=transport))
    return RetryingUpstreamClient(inner, policy_for(cfg))


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# tools/list is always safe to retry
# ---------------------------------------------------------------------------


def test_a_transient_failure_on_list_is_retried_and_recovers() -> None:
    timeout = httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(timeout, timeout, ok_tools())

    async def _run() -> list[str]:
        async with client(transport, max_attempts=3) as c:
            return [t.name for t in await c.list_tools()]

    assert run(_run) == ["search"]
    assert transport.count == 3


def test_list_gives_up_after_max_attempts() -> None:
    timeout = httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(timeout)

    async def _run() -> None:
        async with client(transport, max_attempts=3) as c:
            await c.list_tools()

    with pytest.raises(UpstreamTimeoutError) as exc_info:
        run(_run)

    assert transport.count == 3
    # The typed error survives, carrying what the agent needs.
    assert exc_info.value.upstream == "mock-a"
    assert exc_info.value.recoverable is True


def test_an_unrecoverable_failure_is_never_retried() -> None:
    """Retrying malformed JSON produces the same malformed JSON."""
    transport = CountingTransport(httpx.Response(200, text="{not json"))

    async def _run() -> None:
        async with client(transport, max_attempts=5) as c:
            await c.list_tools()

    with pytest.raises(UpstreamProtocolError):
        run(_run)

    assert transport.count == 1


# ---------------------------------------------------------------------------
# tools/call depends on whether the tool is idempotent
# ---------------------------------------------------------------------------


def test_a_tool_declared_idempotent_is_retried() -> None:
    timeout = httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(timeout, ok_call("found it"))

    async def _run() -> str:
        async with client(transport, max_attempts=3, idempotent_tools=("search",)) as c:
            result = await c.call_tool("search", {"query": "x"})
            return result.text()

    assert run(_run) == "found it"
    assert transport.count == 2


def test_a_tool_not_declared_idempotent_is_called_exactly_once() -> None:
    """The default, and the one that matters.

    A timeout means the gateway received no answer — not that nothing happened.
    The upstream may have filed the ticket and failed to reply. Retrying would
    file a second one, and nothing in the system could tell.
    """
    timeout = httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(timeout)

    async def _run() -> None:
        async with client(transport, max_attempts=5) as c:
            await c.call_tool("create_ticket", {"title": "outage"})

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    assert transport.count == 1, "a non-idempotent tool must never be retried"


def test_declaring_one_tool_idempotent_does_not_cover_another() -> None:
    timeout = httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(timeout)

    async def _run() -> None:
        async with client(transport, max_attempts=5, idempotent_tools=("search",)) as c:
            await c.call_tool("create_ticket", {"title": "outage"})

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    assert transport.count == 1


def test_an_unreachable_upstream_is_retried_for_an_idempotent_tool() -> None:
    refused = httpx.ConnectError("refused", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(refused, refused, ok_call("back"))

    async def _run() -> str:
        async with client(transport, max_attempts=3, idempotent_tools=("search",)) as c:
            return (await c.call_tool("search", {})).text()

    assert run(_run) == "back"
    assert transport.count == 3


def test_a_tool_that_ran_and_failed_is_not_retried() -> None:
    """`isError` is a *result*, not a transport failure.

    The tool ran. Calling it again would not change the answer, and for a
    non-idempotent tool would be actively wrong.
    """
    error_result = httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "not found"}], "isError": True},
        },
    )
    transport = CountingTransport(error_result)

    async def _run() -> bool:
        async with client(transport, max_attempts=5, idempotent_tools=("search",)) as c:
            return (await c.call_tool("search", {})).is_error

    assert run(_run) is True
    assert transport.count == 1


# ---------------------------------------------------------------------------
# The wrapper keeps the client's own contract
# ---------------------------------------------------------------------------


def test_the_wrapper_exposes_the_same_config() -> None:
    transport = CountingTransport(ok_tools())

    async def _run() -> str:
        async with client(transport) as c:
            return c.config.name

    assert run(_run) == "mock-a"


def test_retry_policy_is_derived_from_upstream_config() -> None:
    config = UpstreamConfig(
        name="mock-a", url="http://x/mcp", max_attempts=7, initial_backoff=0.25, max_backoff=9.0
    )
    policy = policy_for(config)

    assert (policy.max_attempts, policy.initial_backoff, policy.max_backoff) == (7, 0.25, 9.0)


def test_unreachable_upstream_surfaces_as_unavailable_after_retries() -> None:
    refused = httpx.ConnectError("refused", request=httpx.Request("POST", "http://mock/mcp"))
    transport = CountingTransport(refused)

    async def _run() -> None:
        async with client(transport, max_attempts=2) as c:
            await c.list_tools()

    with pytest.raises(UpstreamUnavailableError):
        run(_run)

    assert transport.count == 2
