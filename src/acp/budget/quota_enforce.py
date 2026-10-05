"""Turn a quota decision into a refused call, or let it pass.

The quota counterpart to ``enforce_rate_limit``, called in one place on the request path.
"""

from __future__ import annotations

from acp.budget.quota import QuotaCounter
from acp.exceptions import QuotaExceededError


def enforce_quota(
    quota: QuotaCounter, principal: str, now: float, cost: float = 1.0, *, debit: bool = True
) -> None:
    """Spend ``cost`` of ``principal``'s quota, or raise.

    With ``debit=False`` only checks affordability.

    Raises:
        QuotaExceededError: with the same ``retry_after``, ``remaining`` and ``limit``
            fields as the rate-limit refusal. ``remaining`` may be non-zero, since a
            call is refused when it would exceed the limit.
    """
    if (quota.check if debit else quota.affords)(principal, now, cost):
        return
    raise QuotaExceededError(
        "quota exceeded for the current window",
        details={
            "retry_after": quota.retry_after(now),
            "remaining": quota.remaining(principal, now),
            "limit": quota.limit,
        },
    )
