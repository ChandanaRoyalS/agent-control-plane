"""One step that draws a call against both budgets, wherever they are kept.

The request path has one question for the budgets: *may this payer spend this
much right now, and if so, spend it.* ADR 0044 §3 fixed the shape of the
answer — **check both, then debit both**, so that a call the quota refuses does
not spend its rate-limit tokens on the way to being refused — and the gateway
asked it by calling the limiter and the quota in turn, with nothing awaited in
between, which on one process is atomic enough.

With the budgets in a shared store (ADR 0067) that sequence is four round
trips with other replicas writing between them, and "nothing awaits between
the checks and the debits" stops being true. So the step is named here as one
operation, `Budgets.charge`, and each keeper of budget state implements it in
the way that is atomic for it: the in-memory keeper by the same four calls,
and the Redis keeper by one script the server runs without interleaving.

The protocol is ``async`` because one implementation crosses a network and
ADR 0053 forbids blocking the loop. `LocalBudgets` has nothing to await and
awaits nothing; the shape is one shape.
"""

from __future__ import annotations

from typing import Protocol

from acp.budget.enforce import enforce_rate_limit
from acp.budget.quota import QuotaCounter
from acp.budget.quota_enforce import enforce_quota
from acp.budget.ratelimit import RateLimiter


class Budgets(Protocol):
    """Draw ``cost`` from ``payer``'s budgets, or raise the refusal it earns.

    Raises ``RateLimitExceededError`` or ``QuotaExceededError`` — the same two
    errors, with the same three details (``retry_after``, ``remaining``,
    ``limit``), whichever keeper answers. ``mono`` is a monotonic reading for
    the rate and ``wall`` a wall-clock one for the window; a keeper that has
    no monotonic clock shared with the other replicas may use ``wall`` for
    both, and says so.
    """

    async def charge(self, payer: str, cost: float, *, mono: float, wall: float) -> None: ...


class LocalBudgets:
    """The budgets in this process's memory: a limiter, a quota, or both.

    Exactly the sequence `_charge` in the gateway performed before the step
    had a name. Either budget may be absent; with neither there is nothing to
    charge, and the gateway does not build one of these at all.
    """

    def __init__(self, limiter: RateLimiter | None, quota: QuotaCounter | None) -> None:
        self._limiter = limiter
        self._quota = quota

    async def charge(self, payer: str, cost: float, *, mono: float, wall: float) -> None:
        # Check both, then debit both (ADR 0044 §3). Nothing awaits between
        # the checks and the debits, so the two cannot disagree.
        if self._limiter is not None:
            enforce_rate_limit(self._limiter, payer, mono, cost, debit=False)
        if self._quota is not None:
            enforce_quota(self._quota, payer, wall, cost, debit=False)
        if self._limiter is not None:
            enforce_rate_limit(self._limiter, payer, mono, cost)
        if self._quota is not None:
            enforce_quota(self._quota, payer, wall, cost)
