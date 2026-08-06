"""A circuit breaker for one upstream.

Retries (task 13) answer "this attempt failed, try again." They do not answer
the question that follows: *this upstream has failed the last twenty times, why
is every new caller still waiting thirty seconds to find that out?* A dead
upstream with retries and no breaker is worse than one with neither — each
request now costs `max_attempts * read_timeout` before failing, so the gateway's
workers fill with calls that are all going to fail, and the healthy upstreams
starve behind them. Failing fast is the whole point.

**The state machine.**

``CLOSED`` is normal: calls pass through, consecutive failures are counted.
Reaching ``failure_threshold`` trips the breaker to ``OPEN``.

``OPEN`` rejects immediately, without touching the network. After
``reset_timeout`` has elapsed, the next caller moves the breaker to
``HALF_OPEN``.

``HALF_OPEN`` lets a small number of trial calls through — one by default —
while continuing to reject everyone else. If a trial succeeds the breaker
closes; if it fails the breaker re-opens and the clock restarts. This is the
part that distinguishes a breaker from a timer: recovery is *measured*, not
assumed, and exactly one request pays the cost of measuring it.

**Consecutive failures, not a failure rate.** A rate is the more sophisticated
choice and it needs a companion it is easy to forget: a minimum call volume,
without which one failed call out of one is a 100% failure rate and opens the
circuit on a single blip. Consecutive counting encodes that volume requirement
in its own definition — five consecutive failures cannot happen in fewer than
five calls — which is why it is used here.

**What counts as a failure** is narrower than "an exception happened", and
getting it wrong is how a breaker takes a healthy upstream offline. See
:func:`counts_as_failure`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum

import anyio

from acp.exceptions import (
    ACPError,
    UpstreamCircuitOpenError,
    UpstreamOverloadedError,
)
from acp.upstream.config import UpstreamConfig

logger = logging.getLogger(__name__)

Clock = Callable[[], float]
"""Injected so tests can move time without spending it. Monotonic by default —
a wall clock that steps backwards over an NTP correction would leave a breaker
open for an arbitrarily long time."""


class BreakerState(StrEnum):
    """Where the breaker is. A ``StrEnum`` so it logs and serialises as itself."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    """How eagerly to open, and how patiently to recover."""

    failure_threshold: int = 5
    """Consecutive failures that trip the breaker. Too low and a transient blip
    takes the upstream out; too high and the breaker never protects anyone."""

    reset_timeout: float = 30.0
    """Seconds an open breaker waits before allowing a trial call."""

    half_open_max_calls: int = 1
    """Concurrent trial calls permitted while half-open.

    One is the right default. The upstream is, by hypothesis, still fragile —
    sending a burst at the moment it comes back up is how a recovering service
    is knocked over again.
    """


@dataclass(frozen=True, slots=True)
class BreakerSnapshot:
    """A readable view of the breaker, for logs, metrics and health checks.

    Returned as a value rather than exposing the breaker's mutable state, so a
    caller cannot accidentally read a half-applied transition.
    """

    upstream: str
    state: BreakerState
    consecutive_failures: int
    seconds_until_reset: float | None
    """``None`` unless the breaker is open."""

    @property
    def is_available(self) -> bool:
        """Whether a call would currently be let through."""
        return self.state is not BreakerState.OPEN


def breaker_policy_for(config: UpstreamConfig) -> BreakerPolicy:
    """Derive the breaker policy from an upstream's configuration."""
    return BreakerPolicy(
        failure_threshold=config.failure_threshold,
        reset_timeout=config.reset_timeout,
        half_open_max_calls=config.half_open_max_calls,
    )


def counts_as_failure(exc: BaseException) -> bool:
    """Whether this exception is evidence that the upstream is unhealthy.

    Three groups get excluded, each for its own reason.

    *The gateway's own refusals* — an open circuit, a full bulkhead — never
    reached the upstream. Counting them would make the breaker self-reinforcing:
    it opens, its own rejections count as failures, and it can never close.

    *Errors the upstream returned deliberately* — a malformed response, a
    JSON-RPC rejection, an unknown tool. These prove the upstream is alive and
    answering. Opening the circuit on them means an agent sending bad arguments
    can take a perfectly healthy upstream offline for everybody, which is a
    denial of service the gateway inflicts on itself.

    *Anything that is not an ``ACPError`` at all* is a bug in the gateway. It
    should page a human, not condemn the upstream.

    What remains is what the taxonomy already marks ``recoverable``: timeouts
    and unreachability. That this predicate coincides with the retry layer's is
    not an accident to be factored away — both are asking "was this the
    upstream failing to respond?", and the ``recoverable`` flag is where that
    is recorded once.
    """
    if isinstance(exc, UpstreamCircuitOpenError | UpstreamOverloadedError):
        return False
    return isinstance(exc, ACPError) and exc.recoverable


class CircuitBreaker:
    """Tracks one upstream's health and refuses calls when it is failing.

    Guards state with a lock rather than relying on the single-threaded event
    loop. The transitions read state, decide, and write it back; each ``await``
    in between would be a place for another task to interleave and, for example,
    let two probes through a half-open breaker configured to allow one.
    """

    def __init__(
        self,
        upstream: str,
        policy: BreakerPolicy | None = None,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._upstream = upstream
        self._policy = policy or BreakerPolicy()
        self._clock = clock or time.monotonic
        self._lock = anyio.Lock()
        self._state = BreakerState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._probes_in_flight = 0

    # -- observation -------------------------------------------------------

    @property
    def state(self) -> BreakerState:
        """The current state, without the lock.

        Safe because a state read is a single attribute load and callers use it
        for reporting, never to decide whether a call may proceed — that
        decision belongs to :meth:`guard`, which does hold the lock.
        """
        return self._state

    def snapshot(self) -> BreakerSnapshot:
        """A consistent view for logs, metrics and the health endpoint."""
        return BreakerSnapshot(
            upstream=self._upstream,
            state=self._state,
            consecutive_failures=self._consecutive_failures,
            seconds_until_reset=self._seconds_until_reset(),
        )

    # -- the gate ----------------------------------------------------------

    @asynccontextmanager
    async def guard(self) -> AsyncIterator[None]:
        """Wrap one call: refuse it, or watch how it goes.

        A context manager rather than ``before``/``record_success``/
        ``record_failure`` methods, because those can be called in the wrong
        order or forgotten on an exception path, and a half-open probe that is
        never released leaves the breaker permanently refusing everyone.
        """
        await self._enter()
        try:
            yield
        except BaseException as exc:
            await self._leave(exc)
            raise
        await self._leave(None)

    async def _enter(self) -> None:
        async with self._lock:
            if self._state is BreakerState.OPEN:
                remaining = self._seconds_until_reset() or 0.0
                if remaining > 0:
                    raise self._rejected(remaining)
                # The timeout has elapsed: this caller becomes the probe.
                self._state = BreakerState.HALF_OPEN
                self._probes_in_flight = 0
                self._log("breaker.half_open")

            if (
                self._state is BreakerState.HALF_OPEN
                and self._probes_in_flight >= self._policy.half_open_max_calls
            ):
                # Somebody else is already testing the water. Everyone else
                # keeps failing fast until that probe reports back.
                raise self._rejected(self._policy.reset_timeout)

            if self._state is BreakerState.HALF_OPEN:
                self._probes_in_flight += 1

    async def _leave(self, exc: BaseException | None) -> None:
        async with self._lock:
            if self._state is BreakerState.HALF_OPEN:
                self._probes_in_flight = max(0, self._probes_in_flight - 1)

            if exc is None:
                if self._state is not BreakerState.CLOSED:
                    # Only the transition is logged, not every success. A line
                    # per healthy call would bury the three events that matter
                    # under the traffic they are meant to describe.
                    self._log("breaker.closed")
                self._consecutive_failures = 0
                self._state = BreakerState.CLOSED
                self._opened_at = None
                return

            if not counts_as_failure(exc):
                # Neutral. Notably this leaves a half-open breaker half-open
                # rather than closing it: the upstream answering with an error
                # proves it is alive, but the breaker tracks whether calls
                # *succeed*, and a stream of bad-argument calls should not be
                # able to hold the circuit closed over an upstream that never
                # actually serves anything.
                return

            self._consecutive_failures += 1

            if self._state is BreakerState.OPEN:
                # Already open, and this is a call that was in flight when it
                # tripped. Its failure is not new information, and re-opening
                # here would restart the reset timer. With a read timeout close
                # to the reset timeout, a trickle of stragglers landing one
                # after another would push recovery back indefinitely and the
                # breaker would never get as far as a probe.
                return

            if (
                self._state is BreakerState.HALF_OPEN
                or self._consecutive_failures >= self._policy.failure_threshold
            ):
                # A failed probe re-opens immediately, without waiting to
                # accumulate another full threshold. The threshold's job is to
                # decide whether a *healthy* upstream has gone bad; a half-open
                # breaker has already made that call.
                self._state = BreakerState.OPEN
                self._opened_at = self._clock()
                self._log("breaker.opened", level=logging.ERROR, error=type(exc).__name__)

    # -- internals ---------------------------------------------------------

    def _log(self, event: str, *, level: int = logging.WARNING, **fields: object) -> None:
        """One line per state change.

        A breaker opening is the single most important thing this module can
        say: it means a whole upstream has just left the gateway's catalogue as
        far as callers are concerned. ERROR for that, WARNING for the recovery
        steps, and nothing at all for the calls in between.
        """
        logger.log(
            level,
            event,
            extra={
                "upstream": self._upstream,
                "consecutive_failures": self._consecutive_failures,
                "reset_timeout_s": self._policy.reset_timeout,
                **fields,
            },
        )

    def _seconds_until_reset(self) -> float | None:
        if self._state is not BreakerState.OPEN or self._opened_at is None:
            return None
        elapsed = self._clock() - self._opened_at
        return max(0.0, self._policy.reset_timeout - elapsed)

    def _rejected(self, retry_after: float) -> UpstreamCircuitOpenError:
        return UpstreamCircuitOpenError(
            f"circuit open for {self._upstream}: refusing to call an upstream "
            f"that failed {self._consecutive_failures} consecutive times",
            upstream=self._upstream,
            retry_after_seconds=retry_after,
            details={"state": str(self._state)},
        )
