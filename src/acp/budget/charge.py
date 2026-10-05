"""One atomic step that charges a call against both budgets.

Check both, then debit both, so a quota refusal spends no rate tokens (ADR 0044 §3).
Each keeper makes `Budgets.charge` atomic its own way: in memory with no await
between steps, in Redis with one script (ADR 0067). Async because Redis crosses the
network and the loop must not block (ADR 0053).
"""

from __future__ import annotations

from typing import Protocol

from acp.budget.enforce import enforce_rate_limit
from acp.budget.quota import QuotaCounter
from acp.budget.quota_enforce import enforce_quota
from acp.budget.ratelimit import RateLimiter


class Budgets(Protocol):
    """Draw ``cost`` from ``payer``'s budgets, or raise the refusal it earns.

    Raises ``RateLimitExceededError`` or ``QuotaExceededError`` with ``retry_after``,
    ``remaining`` and ``limit``, whichever keeper answers. ``mono`` (monotonic) times
    the rate and ``wall`` the window; a keeper without a shared monotonic clock may
    use ``wall`` for both, and says so.
    """

    async def charge(self, payer: str, cost: float, *, mono: float, wall: float) -> None: ...


class LocalBudgets:
    """In-process budgets: a limiter, a quota, or both (the gateway skips it with neither)."""

    def __init__(self, limiter: RateLimiter | None, quota: QuotaCounter | None) -> None:
        self._limiter = limiter
        self._quota = quota

    async def charge(self, payer: str, cost: float, *, mono: float, wall: float) -> None:
        # Check both, then debit both (ADR 0044 §3); no await between, so atomic.
        if self._limiter is not None:
            enforce_rate_limit(self._limiter, payer, mono, cost, debit=False)
        if self._quota is not None:
            enforce_quota(self._quota, payer, wall, cost, debit=False)
        if self._limiter is not None:
            enforce_rate_limit(self._limiter, payer, mono, cost)
        if self._quota is not None:
            enforce_quota(self._quota, payer, wall, cost)
