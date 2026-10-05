"""A circuit breaker for one upstream, so a dead upstream fails fast.

``CLOSED`` counts consecutive failures and opens at ``failure_threshold``.
``OPEN`` rejects without touching the network until ``reset_timeout``, then the
next caller moves it to ``HALF_OPEN``, which admits ``half_open_max_calls`` probes:
a success closes it, a failure re-opens it. Consecutive counting needs no minimum
call volume. Only some exceptions count; see :func:`counts_as_failure`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum

from acp.exceptions import (
    ACPError,
    CredentialExchangeError,
    UpstreamCircuitOpenError,
    UpstreamOverloadedError,
)
from acp.observability import metrics
from acp.upstream.config import UpstreamConfig

logger = logging.getLogger(__name__)

Clock = Callable[[], float]
"""Injectable for tests; monotonic by default so a wall-clock step cannot strand it open."""


class BreakerState(StrEnum):
    """Where the breaker is. A ``StrEnum`` so it logs and serialises as itself."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    """How eagerly to open, and how patiently to recover."""

    failure_threshold: int = 5
    """Consecutive failures that trip the breaker."""

    reset_timeout: float = 30.0
    """Seconds an open breaker waits before allowing a trial call."""

    half_open_max_calls: int = 1
    """Concurrent trial calls permitted while half-open; one spares a fragile upstream."""


@dataclass(frozen=True, slots=True)
class BreakerSnapshot:
    """An immutable view of the breaker, for logs, metrics and health checks."""

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

    Only ``recoverable`` ``ACPError``s (timeouts, unreachability) count. Excluded:
    the gateway's own refusals (else the breaker could never close), errors the
    upstream returned deliberately (else bad arguments could take it offline),
    ``CredentialExchangeError`` (raised before any byte is sent; else one identity
    outage opens every circuit), and non-``ACPError`` gateway bugs.
    """
    if isinstance(exc, UpstreamCircuitOpenError | UpstreamOverloadedError):
        return False
    if isinstance(exc, CredentialExchangeError):
        return False
    return isinstance(exc, ACPError) and exc.recoverable


class CircuitBreaker:
    """Tracks one upstream's health and refuses calls when it is failing.

    No lock: each transition has no ``await``, so it is atomic on one event loop,
    and the release path has no cancellation point that could strand a probe. If a
    transition ever awaits, add a lock and shield the release from cancellation.
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
        self._state = BreakerState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._probes_in_flight = 0
        self._epoch = 0
        """Bumped on every transition; only a call admitted in the current epoch
        may release a probe slot or change state."""

    # -- observation -------------------------------------------------------

    @property
    def state(self) -> BreakerState:
        """The current state, for reporting only; :meth:`guard` decides admission."""
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

        The release is synchronous and in ``finally``, so no exit path, cancellation
        included, leaves a probe counted in flight. A cancelled call is neutral.
        """
        ticket = self._enter()
        outcome: BaseException | None = None
        try:
            yield
        except BaseException as exc:
            outcome = exc
            raise
        finally:
            self._leave(ticket, outcome)

    def _transition(self, state: BreakerState) -> None:
        self._state = state
        self._epoch += 1

    def _enter(self) -> tuple[int, bool]:
        """Admit a call or raise; return its (epoch, holds-probe-slot) ticket."""
        if self._state is BreakerState.OPEN:
            remaining = self._seconds_until_reset() or 0.0
            if remaining > 0:
                raise self._rejected(remaining)
            # The timeout has elapsed: this caller becomes the probe.
            self._transition(BreakerState.HALF_OPEN)
            self._probes_in_flight = 0
            self._log("breaker.half_open")

        if (
            self._state is BreakerState.HALF_OPEN
            and self._probes_in_flight >= self._policy.half_open_max_calls
        ):
            # A probe is already out; fail fast until it reports back.
            raise self._rejected(self._policy.reset_timeout)

        probe = self._state is BreakerState.HALF_OPEN
        if probe:
            self._probes_in_flight += 1
        return self._epoch, probe

    def _leave(self, ticket: tuple[int, bool], exc: BaseException | None) -> None:
        epoch, probe = ticket
        if probe and epoch == self._epoch:
            self._probes_in_flight = max(0, self._probes_in_flight - 1)

        if epoch != self._epoch:
            # A straggler from an earlier epoch: its outcome must not close,
            # re-open or restart the timer, nor touch the probe count.
            return

        if exc is None:
            recovered = self._state is not BreakerState.CLOSED
            self._consecutive_failures = 0
            if recovered:
                self._transition(BreakerState.CLOSED)
            self._opened_at = None
            if recovered:
                # Logged after the reset so it reports zero failures; only
                # transitions are logged, never each success.
                self._log("breaker.closed")
            return

        if not counts_as_failure(exc):
            # Neutral: a half-open breaker stays half-open, so error replies
            # cannot hold the circuit closed.
            return

        self._consecutive_failures += 1

        if (
            self._state is BreakerState.HALF_OPEN
            or self._consecutive_failures >= self._policy.failure_threshold
        ):
            # A failed probe re-opens immediately, without a full threshold.
            self._transition(BreakerState.OPEN)
            self._opened_at = self._clock()
            self._log("breaker.opened", level=logging.ERROR, error=type(exc).__name__)

    # -- internals ---------------------------------------------------------

    def _log(self, event: str, *, level: int = logging.WARNING, **fields: object) -> None:
        """Log and record one state change; ERROR for opening, WARNING otherwise."""
        metrics.observe_breaker(upstream=self._upstream, state=str(self._state))
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
