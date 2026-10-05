"""A fixed-window quota per principal, bounding total spend where rate limits bound speed.

Windows are clock-aligned (``floor(now / window_seconds)``), so everyone resets at the
same absolute boundary. Time is injected, never read, keeping it pure.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field

from acp.budget.ratelimit import DEFAULT_MAX_PRINCIPALS


@dataclass
class QuotaCounter:
    """Per-principal spend within the current fixed window.

    ``limit`` is the most a principal may spend per window. In-memory and per-process,
    like the rate limiter.
    """

    limit: float
    window_seconds: float
    max_principals: int = DEFAULT_MAX_PRINCIPALS
    # Per principal: (window index, amount spent). Bounded LRU; see `RateLimiter._bucket`.
    _spent: OrderedDict[str, tuple[int, float]] = field(default_factory=OrderedDict)

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
        """Return spend in the window containing ``now``; zero if last spent earlier."""
        entry = self._spent.get(principal)
        if entry is None or entry[0] != self._window_index(now):
            return 0.0
        return entry[1]

    def check(self, principal: str, now: float, cost: float = 1.0) -> bool:
        """Spend ``cost`` of ``principal``'s quota in the current window.

        Returns ``True`` and records it if it fits, else ``False`` and records nothing.
        """
        if not self.affords(principal, now, cost):
            return False
        used = self._used(principal, now)
        self._spent[principal] = (self._window_index(now), used + cost)
        self._spent.move_to_end(principal)
        while len(self._spent) > self.max_principals:
            self._spent.popitem(last=False)
        return True

    def affords(self, principal: str, now: float, cost: float = 1.0) -> bool:
        """Whether ``check`` would succeed, without recording anything."""
        return self._used(principal, now) + cost <= self.limit

    def remaining(self, principal: str, now: float) -> float:
        """How much of the quota is unspent in the current window."""
        return max(0.0, self.limit - self._used(principal, now))

    def resets_at(self, now: float) -> float:
        """The absolute time at which the window containing ``now`` ends."""
        return (self._window_index(now) + 1) * self.window_seconds

    def retry_after(self, now: float) -> float:
        """Seconds from ``now`` until the current window resets."""
        return self.resets_at(now) - now
