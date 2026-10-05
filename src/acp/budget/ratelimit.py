"""A token-bucket rate limiter, per principal, with time injected.

Capacity is the largest burst, refill rate the sustained rate. Time is a parameter,
never read here; the gateway passes a monotonic clock.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Final

DEFAULT_MAX_PRINCIPALS: Final = 10_000
"""Principals remembered before evicting the least recent; a memory ceiling, not sizing."""


@dataclass
class TokenBucket:
    """One principal's bucket; starts full on first use, so a new principal may burst."""

    capacity: float
    refill_per_second: float
    tokens: float = field(default=0.0)
    updated_at: float = field(default=0.0)
    _initialised: bool = field(default=False, repr=False)

    def _refill(self, now: float) -> None:
        if not self._initialised:
            # Start full at first use, so construction needs no clock.
            self.tokens = self.capacity
            self.updated_at = now
            self._initialised = True
            return
        elapsed = now - self.updated_at
        if elapsed <= 0:
            # A stalled or backwards clock adds nothing and never removes tokens.
            return
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated_at = now

    def take(self, now: float, cost: float = 1.0) -> bool:
        """Refill to ``now``, then spend ``cost`` if the bucket can afford it.

        Returns ``True`` and debits if affordable, else ``False`` and leaves it untouched.
        """
        if not self.affords(now, cost):
            return False
        self.tokens -= cost
        return True

    def affords(self, now: float, cost: float = 1.0) -> bool:
        """Refill to ``now`` and return whether ``cost`` could be spent, without spending.

        Lets both budgets be checked before either is debited (ADR 0044 §3).
        """
        self._refill(now)
        return self.tokens >= cost

    def retry_after(self, cost: float = 1.0) -> float:
        """Seconds until the bucket would hold ``cost`` tokens, at the refill rate.

        Zero if affordable now; ``inf`` with a zero refill rate.
        """
        available = self.remaining()
        if available >= cost:
            return 0.0
        shortfall = cost - available
        if self.refill_per_second <= 0:
            return float("inf")
        return shortfall / self.refill_per_second

    def remaining(self) -> float:
        """Tokens available now, without refilling or debiting; full if never used."""
        return self.capacity if not self._initialised else self.tokens


class RateLimiter:
    """Per-principal token buckets sharing one capacity and refill rate.

    In-memory and per-process; `RedisBudgets` is the shared-store keeper for replicas.
    """

    def __init__(
        self,
        capacity: float,
        refill_per_second: float,
        max_principals: int = DEFAULT_MAX_PRINCIPALS,
    ) -> None:
        self._capacity = capacity
        self._refill_per_second = refill_per_second
        self._max_principals = max_principals
        self._buckets: OrderedDict[str, TokenBucket] = OrderedDict()

    @property
    def capacity(self) -> float:
        """The full-bucket burst allowance, reported to refused callers as ``limit``."""
        return self._capacity

    def _bucket(self, principal: str) -> TokenBucket:
        """Return ``principal``'s bucket, created full; LRU-bounded by ``max_principals``.

        Bounded because callers' IdPs choose the keys. A returning evicted principal
        gets a fresh full bucket, only after `max_principals` others were charged.
        """
        bucket = self._buckets.get(principal)
        if bucket is None:
            bucket = TokenBucket(capacity=self._capacity, refill_per_second=self._refill_per_second)
            self._buckets[principal] = bucket
            while len(self._buckets) > self._max_principals:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(principal)
        return bucket

    def check(self, principal: str, now: float, cost: float = 1.0) -> bool:
        """Spend ``cost`` at ``now``; ``True`` and debited if within budget, else ``False``."""
        return self._bucket(principal).take(now, cost)

    def affords(self, principal: str, now: float, cost: float = 1.0) -> bool:
        """Whether ``check`` would succeed, without debiting."""
        return self._bucket(principal).affords(now, cost)

    def retry_after(self, principal: str, cost: float = 1.0) -> float:
        """Seconds ``principal`` should wait; zero for an unseen one, creating no state."""
        bucket = self._buckets.get(principal)
        return 0.0 if bucket is None else bucket.retry_after(cost)

    def remaining(self, principal: str) -> float:
        """How much of ``principal``'s budget is available now (as ``QuotaCounter.remaining``)."""
        bucket = self._buckets.get(principal)
        return self._capacity if bucket is None else bucket.remaining()
