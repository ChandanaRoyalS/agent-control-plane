"""Retrying an upstream call, when and only when that is safe.

Two questions have to be answered before a retry is legitimate, and getting
either wrong is worse than not retrying at all.

**Is this failure worth retrying?** The taxonomy already answers this. Every
``ACPError`` carries ``recoverable``, set deliberately when the class was
defined: a timeout or an unreachable host may well succeed on a second attempt,
while a malformed response will produce the same garbage every time. Retrying
the latter just burns the agent's budget more slowly.

**Is this operation safe to repeat?** ``tools/list`` is a read and always is.
``tools/call`` is not: retrying ``create_ticket`` after a timeout files a second
ticket, and the client cannot tell whether the first one succeeded — a timeout
means *no answer*, not *no effect*. So tool calls are retried only when the
upstream's configuration explicitly names the tool as idempotent. The default is
an empty list, which means no tool call is ever retried unless someone said so.

Backoff uses **full jitter**: the delay is drawn uniformly from ``[0, cap]``
rather than being ``cap`` exactly. When several callers fail against the same
upstream at the same moment — which is precisely what happens when an upstream
restarts — an unjittered backoff synchronises them into a thundering herd that
knocks the upstream over again on each retry round. Full jitter spreads them.
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
    """Ceiling on the backoff cap. Without it, exponential growth quickly
    exceeds any sane request deadline and the retry never happens at all."""

    multiplier: float = 2.0
    """Growth factor per attempt."""

    def backoff_cap(self, attempt: int) -> float:
        """The upper bound for the delay before ``attempt`` (1-based retry index)."""
        raw = self.initial_backoff * (self.multiplier ** (attempt - 1))
        return min(raw, self.max_backoff)


def is_retryable(exc: BaseException) -> bool:
    """Whether this failure could plausibly succeed on another attempt *here*.

    Delegates entirely to the taxonomy rather than matching on exception types,
    because having two places decide "is this worth retrying" is how they drift
    apart. Two flags, not one, and both must hold.

    ``recoverable`` is the advice already forwarded to the agent: this failure
    is not permanent. ``retry_locally`` narrows it to the current request: an
    attempt in the next few hundred milliseconds could change the outcome. They
    differ exactly where the gateway itself refused the call — an open circuit
    or a full bulkhead is recoverable on the agent's timescale and immovable on
    this one, and retrying it would spend the whole attempt budget waiting for a
    gate that has not had time to open.
    """
    return isinstance(exc, ACPError) and exc.recoverable and exc.retry_locally


# and this project targets 3.12+, but a plain TypeVar parses under every
# toolchain that might read this file, which matters more than the syntax.
async def with_retry(  # noqa: UP047
    operation: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    sleep: SleepFn | None = None,
    uniform: RandomFn | None = None,
    on_retry: Callable[[int, float, BaseException], None] | None = None,
) -> T:
    """Run ``operation``, retrying recoverable failures with jittered backoff.

    The last failure is re-raised unchanged, so the caller still receives a
    typed taxonomy error carrying its ``recoverable`` hint and upstream name —
    a retry wrapper that flattens everything into a generic "retries exhausted"
    would destroy exactly the information the agent needs.
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
