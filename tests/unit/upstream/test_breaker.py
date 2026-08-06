"""Unit tests for the circuit breaker state machine.

Time is injected rather than slept through. A breaker whose tests wait out a
real thirty-second reset is a breaker whose reset timeout can never be raised,
and the timing rules are the part most worth testing carefully.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from acp.exceptions import (
    UpstreamCircuitOpenError,
    UpstreamProtocolError,
    UpstreamRejectedError,
    UpstreamTimeoutError,
)
from acp.upstream.breaker import (
    BreakerPolicy,
    BreakerState,
    CircuitBreaker,
    breaker_policy_for,
    counts_as_failure,
)
from acp.upstream.config import UpstreamConfig
from acp.upstream.retry import is_retryable


class FakeClock:
    """A monotonic clock that only moves when a test says so."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def breaker(clock: FakeClock | None = None, **policy: Any) -> CircuitBreaker:
    return CircuitBreaker("mock-a", BreakerPolicy(**policy), clock=clock or FakeClock())


def timeout() -> UpstreamTimeoutError:
    return UpstreamTimeoutError("too slow", upstream="mock-a")


def run(fn: Any) -> Any:
    return anyio.run(fn)


async def fail(cb: CircuitBreaker, exc: BaseException | None = None) -> None:
    """Run one call through the breaker that raises."""
    with pytest.raises(type(exc or timeout())):
        async with cb.guard():
            raise exc or timeout()


async def succeed(cb: CircuitBreaker) -> None:
    async with cb.guard():
        pass


# ---------------------------------------------------------------------------
# Closed: counting up to the threshold
# ---------------------------------------------------------------------------


def test_a_new_breaker_is_closed() -> None:
    cb = breaker()

    assert cb.state is BreakerState.CLOSED
    assert cb.snapshot().is_available
    assert cb.snapshot().seconds_until_reset is None


def test_failures_below_the_threshold_do_not_open_it() -> None:
    cb = breaker(failure_threshold=3)

    async def _run() -> None:
        await fail(cb)
        await fail(cb)

    run(_run)

    assert cb.state is BreakerState.CLOSED
    assert cb.snapshot().consecutive_failures == 2


def test_reaching_the_threshold_opens_it() -> None:
    cb = breaker(failure_threshold=3)

    async def _run() -> None:
        for _ in range(3):
            await fail(cb)

    run(_run)

    assert cb.state is BreakerState.OPEN
    assert not cb.snapshot().is_available


def test_one_success_resets_the_count() -> None:
    """Consecutive, not cumulative — otherwise every long-lived upstream
    eventually accumulates enough failures to trip on a healthy day."""
    cb = breaker(failure_threshold=3)

    async def _run() -> None:
        await fail(cb)
        await fail(cb)
        await succeed(cb)
        await fail(cb)
        await fail(cb)

    run(_run)

    assert cb.state is BreakerState.CLOSED
    assert cb.snapshot().consecutive_failures == 2


# ---------------------------------------------------------------------------
# Open: refusing, and saying for how long
# ---------------------------------------------------------------------------


def test_an_open_breaker_refuses_without_running_the_call() -> None:
    cb = breaker(failure_threshold=1)
    ran = False

    async def _run() -> None:
        nonlocal ran
        await fail(cb)
        async with cb.guard():
            ran = True

    with pytest.raises(UpstreamCircuitOpenError):
        run(_run)

    assert ran is False, "an open circuit must not reach the upstream at all"


def test_the_rejection_tells_the_agent_how_long_to_wait() -> None:
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=1, reset_timeout=30.0)

    async def _run() -> float:
        await fail(cb)
        clock.advance(12.0)
        try:
            await succeed(cb)
        except UpstreamCircuitOpenError as exc:
            return exc.retry_after_seconds
        raise AssertionError("expected the circuit to be open")

    assert run(_run) == pytest.approx(18.0)


def test_the_rejection_is_recoverable_but_not_locally_retryable() -> None:
    """The two flags disagree here, and that disagreement is the point.

    The agent should be told to come back; the gateway's own retry loop should
    not sit in a millisecond backoff waiting out a thirty-second gate.
    """
    exc = UpstreamCircuitOpenError("open", upstream="mock-a", retry_after_seconds=30.0)

    assert exc.recoverable is True
    assert is_retryable(exc) is False


def test_a_straggler_failing_after_it_opened_does_not_restart_the_clock() -> None:
    """The starvation case.

    A call that was already in flight when the breaker tripped lands one read
    timeout later. If its failure re-opened the breaker, and read timeout is
    near reset timeout, a steady trickle of stragglers would push the first
    probe out forever and the upstream could never be found healthy again.
    """
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=1, reset_timeout=30.0)

    async def _run() -> float | None:
        entered = anyio.Event()
        release = anyio.Event()

        async def straggler() -> None:
            # Admitted while the breaker was still closed, so it is inside the
            # guard when the breaker trips underneath it.
            with pytest.raises(UpstreamTimeoutError):  # noqa: PT012
                async with cb.guard():
                    entered.set()
                    await release.wait()
                    raise timeout()

        async with anyio.create_task_group() as tg:
            tg.start_soon(straggler)
            await entered.wait()
            await fail(cb)  # opens at t=0
            clock.advance(29.0)
            release.set()  # the straggler now lands, one read timeout late

        return cb.snapshot().seconds_until_reset

    assert run(_run) == pytest.approx(1.0), "the reset timer must not have moved"


# ---------------------------------------------------------------------------
# Half-open: measuring recovery instead of assuming it
# ---------------------------------------------------------------------------


def test_after_the_reset_timeout_one_call_is_let_through() -> None:
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=1, reset_timeout=30.0)
    reached = False

    async def _run() -> None:
        nonlocal reached
        await fail(cb)
        clock.advance(30.0)
        async with cb.guard():
            reached = True

    run(_run)

    assert reached is True
    assert cb.state is BreakerState.CLOSED, "a successful probe closes the circuit"


def test_a_failed_probe_reopens_and_restarts_the_timer() -> None:
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=5, reset_timeout=30.0)

    async def _run() -> float | None:
        for _ in range(5):
            await fail(cb)
        clock.advance(30.0)
        await fail(cb)  # the probe fails
        return cb.snapshot().seconds_until_reset

    assert run(_run) == pytest.approx(30.0)
    assert cb.state is BreakerState.OPEN


def test_a_failed_probe_reopens_without_waiting_for_another_threshold() -> None:
    """One failed probe is enough. The threshold answers a different question:
    whether an upstream believed healthy has gone bad."""
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=5, reset_timeout=1.0)

    async def _run() -> None:
        for _ in range(5):
            await fail(cb)
        clock.advance(1.0)
        await fail(cb)
        # Still open: the very next caller is refused.
        with pytest.raises(UpstreamCircuitOpenError):
            await succeed(cb)

    run(_run)


def test_only_one_probe_is_admitted_while_half_open() -> None:
    """The burst that kills a recovering service.

    Without this, every caller queued behind an open breaker is released at the
    same instant the reset timeout expires, and the upstream that just came
    back up receives the whole backlog at once.
    """
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=1, reset_timeout=5.0, half_open_max_calls=1)
    admitted = 0
    refused = 0

    async def _run() -> None:
        nonlocal admitted, refused
        await fail(cb)
        clock.advance(5.0)

        release = anyio.Event()

        async def caller() -> None:
            nonlocal admitted, refused
            try:
                async with cb.guard():
                    admitted += 1
                    await release.wait()
            except UpstreamCircuitOpenError:
                refused += 1

        async with anyio.create_task_group() as tg:
            for _ in range(5):
                tg.start_soon(caller)
            await anyio.sleep(0.05)
            release.set()

    run(_run)

    assert admitted == 1
    assert refused == 4


def test_half_open_admits_as_many_probes_as_configured() -> None:
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=1, reset_timeout=5.0, half_open_max_calls=3)
    admitted = 0

    async def _run() -> None:
        nonlocal admitted
        await fail(cb)
        clock.advance(5.0)
        release = anyio.Event()

        async def caller() -> None:
            nonlocal admitted
            try:
                async with cb.guard():
                    admitted += 1
                    await release.wait()
            except UpstreamCircuitOpenError:
                pass

        async with anyio.create_task_group() as tg:
            for _ in range(6):
                tg.start_soon(caller)
            await anyio.sleep(0.05)
            release.set()

    run(_run)

    assert admitted == 3


# ---------------------------------------------------------------------------
# What counts as a failure — the part that decides whether the breaker helps
# ---------------------------------------------------------------------------


def test_a_rejection_by_a_healthy_upstream_never_opens_the_circuit() -> None:
    """An agent sending bad arguments must not be able to take a working
    upstream offline for every other caller."""
    cb = breaker(failure_threshold=2)

    async def _run() -> None:
        for _ in range(10):
            await fail(
                cb, UpstreamRejectedError("no such tool", upstream="mock-a", upstream_code=-32601)
            )

    run(_run)

    assert cb.state is BreakerState.CLOSED
    assert cb.snapshot().consecutive_failures == 0


def test_a_malformed_response_does_not_open_the_circuit() -> None:
    """It answered. It answered badly, which is a bug to fix upstream, not an
    outage to route around — and the taxonomy already says do not retry it."""
    cb = breaker(failure_threshold=2)

    async def _run() -> None:
        for _ in range(5):
            await fail(cb, UpstreamProtocolError("not json", upstream="mock-a"))

    run(_run)

    assert cb.state is BreakerState.CLOSED


def test_a_gateway_bug_does_not_condemn_the_upstream() -> None:
    cb = breaker(failure_threshold=2)

    async def _run() -> None:
        for _ in range(5):
            with pytest.raises(ZeroDivisionError):
                async with cb.guard():
                    raise ZeroDivisionError

    run(_run)

    assert cb.state is BreakerState.CLOSED


def test_the_breakers_own_rejection_is_not_counted_against_it() -> None:
    """Otherwise the breaker is self-reinforcing: it opens, its refusals count
    as failures, and it can never close."""
    assert (
        counts_as_failure(
            UpstreamCircuitOpenError("open", upstream="mock-a", retry_after_seconds=1.0)
        )
        is False
    )


def test_a_neutral_failure_leaves_a_half_open_breaker_half_open() -> None:
    """It releases the probe without judging it, so the next caller gets a real
    trial rather than being refused forever."""
    clock = FakeClock()
    cb = breaker(clock, failure_threshold=1, reset_timeout=5.0)

    async def _run() -> None:
        await fail(cb)
        clock.advance(5.0)
        await fail(cb, UpstreamProtocolError("not json", upstream="mock-a"))
        assert cb.state is BreakerState.HALF_OPEN
        await succeed(cb)

    run(_run)

    assert cb.state is BreakerState.CLOSED


# ---------------------------------------------------------------------------
# Contract details
# ---------------------------------------------------------------------------


def test_the_original_exception_is_re_raised_unchanged() -> None:
    """The breaker observes; it does not rewrite. Flattening the taxonomy here
    would destroy the `recoverable` hint the agent acts on."""
    cb = breaker(failure_threshold=10)
    original = timeout()

    async def _run() -> None:
        async with cb.guard():
            raise original

    with pytest.raises(UpstreamTimeoutError) as exc_info:
        run(_run)

    assert exc_info.value is original


def test_policy_is_derived_from_upstream_config() -> None:
    config = UpstreamConfig(
        name="mock-a",
        url="http://x/mcp",
        failure_threshold=9,
        reset_timeout=2.5,
        half_open_max_calls=4,
    )

    policy = breaker_policy_for(config)

    assert (policy.failure_threshold, policy.reset_timeout, policy.half_open_max_calls) == (
        9,
        2.5,
        4,
    )


def test_the_snapshot_names_the_upstream() -> None:
    """Health output and metrics both need to say *which* upstream is out."""
    assert breaker().snapshot().upstream == "mock-a"
