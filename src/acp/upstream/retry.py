"""Retrying an upstream call, when and only when that is safe.

Only failures the taxonomy marks retryable are retried. ``tools/list`` is always
safe to repeat; ``tools/call`` is retried only for tools the upstream config names
idempotent (default: none), since a timeout means no answer, not no effect. Backoff
uses full jitter, uniform over ``[0, cap]``, so callers failing together do not retry
in lockstep.
"""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

import anyio

from acp.exceptions import ACPError

SleepFn = Callable[[float], Awaitable[None]]
"""Injected so tests can assert on delays without waiting for them."""

RandomFn = Callable[[float, float], float]
"""Injected so tests get deterministic jitter. Signature matches random.uniform."""

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How many times to retry, and how long to wait between attempts."""

    max_attempts: int = 3
    """Total attempts including the first. 1 disables retrying entirely."""

    initial_backoff: float = 0.1
    """Seconds before the first retry, before jitter."""

    max_backoff: float = 5.0
    """Ceiling on the backoff cap, in seconds."""

    multiplier: float = 2.0
    """Growth factor per attempt."""

    def backoff_cap(self, attempt: int) -> float:
        """The upper bound for the delay before ``attempt`` (1-based retry index)."""
        raw = self.initial_backoff * (self.multiplier ** (attempt - 1))
        return min(raw, self.max_backoff)


def is_retryable(exc: BaseException) -> bool:
    """Whether this failure could succeed on another attempt within this request.

    Both taxonomy flags must hold: ``recoverable`` (not permanent) and
    ``retry_locally``, which is false for the gateway's own refusals (open circuit,
    full bulkhead) that will not clear within a backoff.
    """
    return isinstance(exc, ACPError) and exc.recoverable and exc.retry_locally


# Plain TypeVar, not PEP 695, so every toolchain parses it.
async def with_retry(  # noqa: UP047
    operation: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    sleep: SleepFn | None = None,
    uniform: RandomFn | None = None,
    on_retry: Callable[[int, float, BaseException], None] | None = None,
) -> T:
    """Run ``operation``, retrying recoverable failures with jittered backoff.

    The last failure is re-raised unchanged, keeping its typed taxonomy error.
    """
    sleep = sleep or anyio.sleep
    uniform = uniform or random.uniform

    attempt = 1
    while True:
        try:
            return await operation()
        except BaseException as exc:
            if attempt >= policy.max_attempts or not is_retryable(exc):
                raise
            delay = uniform(0.0, policy.backoff_cap(attempt))
            if on_retry is not None:
                on_retry(attempt, delay, exc)
            await sleep(delay)
            attempt += 1
