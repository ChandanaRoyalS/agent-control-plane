"""A fixed-window quota, per principal, with time injected.

Rate limiting (task 38) bounds the *rate* — how fast a principal may call. A
quota bounds the *total* over a longer window — how many calls in an hour, a day.
The two are complementary: a slow drip that never trips the rate limit can still
run up unbounded spend over a day, and a quota is what stops it.

The window is clock-aligned, not anchored to first use: the window containing
``now`` is ``floor(now / window_seconds)``, so a daily quota resets at the same
absolute boundary for everyone rather than 24 hours after each principal's first
call. That is what a deployer means by "1000 a day" — a calendar day, the same
for all — and it makes the reset time answerable without remembering when anyone
started. Time is injected, never read from a clock inside, so the whole thing is
pure and tested by advancing ``now`` across boundaries by hand.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class QuotaCounter:
    """Per-principal spend within the current fixed window.

    ``limit`` is the most a principal may spend in a window of
    ``window_seconds``; the window is clock-aligned, so it resets at absolute
    boundaries and the count starts again from zero. In-memory and per-process,
    like the rate limiter, and for the same reason — correct for a single
    gateway, with a shared store across replicas left as a later extension.
    """

    limit: float
    window_seconds: float
    # Per principal: (window index that the tally belongs to, amount spent in it).
    _spent: dict[str, tuple[int, float]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.limit <= 0:
            msg = "quota limit must be positive"
            raise ValueError(msg)
        if self.window_seconds <= 0:
            msg = "quota window must be positive"
            raise ValueError(msg)

    def _window_index(self, now: float) -> int:
        return math.floor(now / self.window_seconds)

    def _used(self, principal: str, now: float) -> float:
        """Spend recorded for ``principal`` in the window containing ``now`` —
        zero if their last spend was in an earlier window (it has since reset)."""
        entry = self._spent.get(principal)
        if entry is None or entry[0] != self._window_index(now):
            return 0.0
        return entry[1]

    def check(self, principal: str, now: float, cost: float = 1.0) -> bool:
        """Spend ``cost`` of ``principal``'s quota in the current window.

        Returns ``True`` and records the spend when it fits within the limit,
        ``False`` and records nothing when it would exceed it.
        """
        used = self._used(principal, now)
        if used + cost > self.limit:
            return False
        self._spent[principal] = (self._window_index(now), used + cost)
        return True

    def remaining(self, principal: str, now: float) -> float:
        """How much of the quota is unspent in the current window."""
        return max(0.0, self.limit - self._used(principal, now))

    def resets_at(self, now: float) -> float:
        """The absolute time at which the window containing ``now`` ends."""
        return (self._window_index(now) + 1) * self.window_seconds

    def retry_after(self, now: float) -> float:
        """Seconds from ``now`` until the current window resets."""
        return self.resets_at(now) - now
