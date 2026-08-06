"""Tests for retry behaviour.

Sleep and jitter are injected throughout, so these run instantly and assert on
exact delays rather than on wall-clock timing. A retry test that actually sleeps
is a slow test that also cannot check what it most needs to check.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from acp.exceptions import (
    ConfigurationError,
    UpstreamProtocolError,
    UpstreamRejectedError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from acp.upstream.retry import RetryPolicy, is_retryable, with_retry


class Recorder:
    """Captures the delays that would have been slept, without sleeping."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.delays.append(seconds)


def upper_bound(low: float, high: float) -> float:
    """Deterministic stand-in for random.uniform: always the cap."""
    del low
    return high


def lower_bound(low: float, high: float) -> float:
    del high
    return low


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# What is worth retrying
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        UpstreamTimeoutError("slow", upstream="mock-a"),
        UpstreamUnavailableError("down", upstream="mock-a"),
    ],
)
def test_recoverable_failures_are_retryable(exc: Exception) -> None:
    assert is_retryable(exc)


@pytest.mark.parametrize(
    "exc",
    [
        UpstreamProtocolError("garbage", upstream="mock-a"),
        UpstreamRejectedError("no", upstream="mock-a", upstream_code=-32602),
        ConfigurationError("bad config"),
        ValueError("not even ours"),
    ],
)
def test_unrecoverable_failures_are_not_retryable(exc: Exception) -> None:
    """Retrying a malformed response produces the same malformed response.

    The only thing achieved is spending the agent's budget more slowly.
    """
    assert not is_retryable(exc)


def test_retryability_comes_from_the_taxonomy_not_a_type_list() -> None:
    """Guards against the two definitions drifting apart.

    `recoverable` is already what the gateway forwards to the agent to tell it
    whether to try again. If retry logic matched on exception types instead,
    the gateway could tell the agent "recoverable" while itself refusing to
    retry — or the reverse.
    """

    class NewRecoverableError(UpstreamTimeoutError):
        pass

    assert is_retryable(NewRecoverableError("x", upstream="mock-a"))


# ---------------------------------------------------------------------------
# Backoff
# ---------------------------------------------------------------------------


def test_backoff_grows_exponentially() -> None:
    policy = RetryPolicy(initial_backoff=0.1, multiplier=2.0, max_backoff=100.0)

    assert [policy.backoff_cap(n) for n in (1, 2, 3, 4)] == [0.1, 0.2, 0.4, 0.8]


def test_backoff_is_capped() -> None:
    """Without a cap, exponential growth exceeds any sane deadline within a few
    attempts and the retry effectively never happens."""
    policy = RetryPolicy(initial_backoff=1.0, multiplier=10.0, max_backoff=5.0)

    assert [policy.backoff_cap(n) for n in (1, 2, 3)] == [1.0, 5.0, 5.0]


def test_jitter_is_drawn_from_zero_to_the_cap() -> None:
    """Full jitter, not equal jitter or none.

    When several callers fail against the same upstream at the same instant —
    exactly what happens when an upstream restarts — an unjittered backoff
    synchronises them into a herd that knocks it over again on every round.
    """
    recorder = Recorder()
    calls = 0

    async def always_times_out() -> str:
        nonlocal calls
        calls += 1
        raise UpstreamTimeoutError("slow", upstream="mock-a")

    async def _run() -> None:
        await with_retry(
            always_times_out,
            RetryPolicy(max_attempts=4, initial_backoff=1.0, multiplier=2.0),
            sleep=recorder.sleep,
            uniform=lower_bound,
        )

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    # lower_bound picks the bottom of the range, proving the range starts at 0.
    assert recorder.delays == [0.0, 0.0, 0.0]


def test_delays_follow_the_caps_when_jitter_picks_the_top() -> None:
    recorder = Recorder()

    async def always_times_out() -> str:
        raise UpstreamTimeoutError("slow", upstream="mock-a")

    async def _run() -> None:
        await with_retry(
            always_times_out,
            RetryPolicy(max_attempts=4, initial_backoff=0.1, multiplier=2.0),
            sleep=recorder.sleep,
            uniform=upper_bound,
        )

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    assert recorder.delays == [0.1, 0.2, 0.4]


# ---------------------------------------------------------------------------
# Attempt counting
# ---------------------------------------------------------------------------


def test_success_on_the_first_attempt_never_sleeps() -> None:
    recorder = Recorder()

    async def ok() -> str:
        return "fine"

    async def _run() -> str:
        return await with_retry(ok, RetryPolicy(), sleep=recorder.sleep, uniform=upper_bound)

    assert run(_run) == "fine"
    assert recorder.delays == []


def test_a_transient_failure_is_recovered_from() -> None:
    recorder = Recorder()
    attempts = 0

    async def flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise UpstreamUnavailableError("down", upstream="mock-a")
        return "recovered"

    async def _run() -> str:
        return await with_retry(
            flaky, RetryPolicy(max_attempts=5), sleep=recorder.sleep, uniform=upper_bound
        )

    assert run(_run) == "recovered"
    assert attempts == 3
    assert len(recorder.delays) == 2


def test_max_attempts_counts_the_first_try() -> None:
    """`max_attempts=3` means three calls total, not three retries after one."""
    recorder = Recorder()
    attempts = 0

    async def always_fails() -> str:
        nonlocal attempts
        attempts += 1
        raise UpstreamTimeoutError("slow", upstream="mock-a")

    async def _run() -> None:
        await with_retry(
            always_fails, RetryPolicy(max_attempts=3), sleep=recorder.sleep, uniform=upper_bound
        )

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    assert attempts == 3
    assert len(recorder.delays) == 2


def test_max_attempts_of_one_disables_retrying() -> None:
    recorder = Recorder()
    attempts = 0

    async def always_fails() -> str:
        nonlocal attempts
        attempts += 1
        raise UpstreamTimeoutError("slow", upstream="mock-a")

    async def _run() -> None:
        await with_retry(
            always_fails, RetryPolicy(max_attempts=1), sleep=recorder.sleep, uniform=upper_bound
        )

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    assert attempts == 1
    assert recorder.delays == []


def test_unrecoverable_failure_is_not_retried_at_all() -> None:
    recorder = Recorder()
    attempts = 0

    async def malformed() -> str:
        nonlocal attempts
        attempts += 1
        raise UpstreamProtocolError("garbage", upstream="mock-a")

    async def _run() -> None:
        await with_retry(
            malformed, RetryPolicy(max_attempts=5), sleep=recorder.sleep, uniform=upper_bound
        )

    with pytest.raises(UpstreamProtocolError):
        run(_run)

    assert attempts == 1
    assert recorder.delays == []


# ---------------------------------------------------------------------------
# The final failure must survive intact
# ---------------------------------------------------------------------------


def test_the_original_error_is_re_raised_unchanged() -> None:
    """A wrapper that flattened this into "retries exhausted" would destroy the
    upstream name and the recoverable hint the agent needs."""
    recorder = Recorder()

    async def always_fails() -> str:
        raise UpstreamTimeoutError(
            "mock-a did not respond", upstream="mock-a", details={"method": "tools/list"}
        )

    async def _run() -> None:
        await with_retry(
            always_fails, RetryPolicy(max_attempts=2), sleep=recorder.sleep, uniform=upper_bound
        )

    with pytest.raises(UpstreamTimeoutError) as exc_info:
        run(_run)

    assert exc_info.value.upstream == "mock-a"
    assert exc_info.value.recoverable is True
    assert exc_info.value.details["method"] == "tools/list"


def test_on_retry_is_called_with_attempt_delay_and_cause() -> None:
    """The hook exists so retries are observable rather than silent.

    A retry nobody can see turns a degraded upstream into unexplained latency.
    Task 15 wires this to structured logging and task 17 to a metric.
    """
    recorder = Recorder()
    observed: list[tuple[int, float, str]] = []

    async def always_fails() -> str:
        raise UpstreamTimeoutError("slow", upstream="mock-a")

    async def _run() -> None:
        await with_retry(
            always_fails,
            RetryPolicy(max_attempts=3, initial_backoff=0.1),
            sleep=recorder.sleep,
            uniform=upper_bound,
            on_retry=lambda n, d, e: observed.append((n, d, type(e).__name__)),
        )

    with pytest.raises(UpstreamTimeoutError):
        run(_run)

    assert observed == [
        (1, 0.1, "UpstreamTimeoutError"),
        (2, 0.2, "UpstreamTimeoutError"),
    ]


def test_cancellation_is_never_retried() -> None:
    """Cancellation is not a failure to recover from — it is a deliberate stop.

    Retrying through a cancelled scope would make shutdown hang, which is the
    kind of bug that only shows up under SIGTERM in production.
    """
    recorder = Recorder()
    attempts = 0

    async def _run() -> None:
        nonlocal attempts
        # `get_cancelled_exc_class` must be called from inside a running loop —
        # it reports the backend's own cancellation type, which is asyncio's
        # under asyncio and trio's under trio.
        cancelled_exc = anyio.get_cancelled_exc_class()

        async def cancelled() -> str:
            nonlocal attempts
            attempts += 1
            raise cancelled_exc

        with pytest.raises(cancelled_exc):
            await with_retry(
                cancelled, RetryPolicy(max_attempts=5), sleep=recorder.sleep, uniform=upper_bound
            )

    run(_run)

    assert attempts == 1
    assert recorder.delays == []
