"""A token-bucket rate limiter, per principal, with time injected.

The bucket is the classic shape: a capacity (the largest burst allowed) and a
refill rate (tokens added per second, the sustained rate). Each call costs one
token; a call with no token available is refused, and the caller is told how long
until one returns.

Time is a parameter, never read from a clock inside. That keeps the whole thing
pure and testable — a test advances ``now`` by hand and asserts the exact
transition, the same discipline the policy evaluator follows. The gateway passes
a real monotonic clock at the one call site; the logic here never depends on it.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Final

DEFAULT_MAX_PRINCIPALS: Final = 10_000
"""Distinct principals a limiter remembers before forgetting the least recent.

Ten thousand buckets is under a megabyte. The number is a ceiling on memory an
authenticated caller can make the gateway hold, not a sizing estimate.
"""


@dataclass
class TokenBucket:
    """One principal's bucket: how many tokens remain, and when it last refilled.

    ``capacity`` is the burst ceiling and the value the bucket refills toward;
    ``refill_per_second`` is the sustained rate. ``tokens`` starts full, so a
    fresh principal may burst up to ``capacity`` immediately.
    """

    capacity: float
    refill_per_second: float
    tokens: float = field(default=0.0)
    updated_at: float = field(default=0.0)
    _initialised: bool = field(default=False, repr=False)

    def _refill(self, now: float) -> None:
        if not self._initialised:
            # First sight of this bucket: start full, anchored at now. Done here
            # rather than in __init__ so the caller need not know the clock to
            # construct one.
            self.tokens = self.capacity
            self.updated_at = now
            self._initialised = True
            return
        elapsed = now - self.updated_at
        if elapsed <= 0:
            # Clock did not advance (or went backwards — a monotonic clock will
            # not, but be defensive): add nothing, and never remove tokens.
            return
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated_at = now

    def take(self, now: float, cost: float = 1.0) -> bool:
        """Refill to ``now``, then spend ``cost`` if the bucket can afford it.

        Returns ``True`` and debits the bucket when there are enough tokens,
        ``False`` and leaves it untouched otherwise.
        """
        if not self.affords(now, cost):
            return False
        self.tokens -= cost
        return True

    def affords(self, now: float, cost: float = 1.0) -> bool:
        """Refill to ``now`` and say whether ``cost`` could be spent — without
        spending it.

        The half of `take` that lets two budgets be checked before either is
        debited (ADR 0044 §3): a call refused by the quota must not have spent
        its rate-limit tokens on the way to being refused.
        """
        self._refill(now)
        return self.tokens >= cost

    def retry_after(self, cost: float = 1.0) -> float:
        """Seconds until the bucket would hold ``cost`` tokens, at the refill rate.

        A hint for the caller. Zero when a token is already available; otherwise
        the shortfall divided by the rate. With a zero refill rate the wait is
        unbounded, reported as ``inf``.
        """
        # A bucket never yet taken from is full (it initialises full on first
        # take), so nothing is owed — asking retry_after before any call must not
        # read the pre-initialisation zero as an empty bucket.
        available = self.remaining()
        if available >= cost:
            return 0.0
        shortfall = cost - available
        if self.refill_per_second <= 0:
            return float("inf")
        return shortfall / self.refill_per_second

    def remaining(self) -> float:
        """Tokens available right now, without refilling or debiting.

        The other half of what a refused caller needs. ``retry_after`` says
        *when* they may try again; this says *how much* they may still do, which
        is the difference between an agent that backs off and one that plans —
        it can decide to spend what is left on the three calls that matter
        rather than burning it on the first three it thought of.

        A bucket never yet taken from reports its full capacity. It initialises
        full on first take, so reading the pre-initialisation zero would tell a
        caller who has done nothing that they have nothing left. That is the same
        correction ``retry_after`` makes, which is why it now reads this rather
        than repeating it.
        """
        return self.capacity if not self._initialised else self.tokens


class RateLimiter:
    """Per-principal token buckets sharing one capacity and refill rate.

    Holds a bucket per principal subject, created full on first sight. Purely
    in-memory and per-process: correct for a single gateway, and deliberately so
    for this first budget control — a distributed limiter (shared store across
    replicas) is a later extension the interface here leaves room for, not
    something the concept needs to be demonstrated.
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
        """The burst allowance every principal's bucket holds when full.

        Public because a refused caller is told it: ``remaining`` alone is a
        number without a scale, and "2 left" means something different out of 5
        than out of 500. The pair is what lets an agent judge how hard it is
        being throttled rather than only that it is.
        """
        return self._capacity

    def _bucket(self, principal: str) -> TokenBucket:
        """``principal``'s bucket, created full on first sight — and bounded.

        **Bounded, because an authenticated caller chooses the keys.** The
        subject space is whatever the identity provider mints, and a tenant's
        IdP issuing short-lived per-session subjects would grow this dict
        without limit. The result cache is bounded for exactly this reason; the
        budgets were not. Least-recently-charged is evicted. An evicted
        principal who returns gets a fresh, full bucket — a burst allowance,
        not an escalation, and only after `max_principals` *others* have been
        charged since they last were.
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
        """Try to spend one unit of ``principal``'s budget at time ``now``.

        ``True`` if the call is within budget (and the budget is debited),
        ``False`` if the principal is over their limit.
        """
        return self._bucket(principal).take(now, cost)

    def affords(self, principal: str, now: float, cost: float = 1.0) -> bool:
        """Whether ``check`` would succeed, without debiting."""
        return self._bucket(principal).affords(now, cost)

    def retry_after(self, principal: str, cost: float = 1.0) -> float:
        """How long ``principal`` should wait before retrying, in seconds.

        A principal never seen has a full bucket and owes nothing; asking does
        not create state for them.
        """
        bucket = self._buckets.get(principal)
        return 0.0 if bucket is None else bucket.retry_after(cost)

    def remaining(self, principal: str) -> float:
        """How much of ``principal``'s budget is available right now.

        Named to match ``QuotaCounter.remaining`` so the two budgets answer the
        same question with the same word — a refused caller should not have to
        know which of the two stopped them to read the answer.
        """
        bucket = self._buckets.get(principal)
        return self._capacity if bucket is None else bucket.remaining()
