"""Turn a quota decision into a refused call, or let it pass.

The quota counterpart to ``enforce_rate_limit``: a pure boundary the request
path calls in one place. The quota decides whether the principal has budget left
in the current window; this raises ``QuotaExceededError`` when they do not,
carrying a ``retry_after`` hint so a well-behaved agent knows to wait for the
window rather than keep trying.
"""

from __future__ import annotations

from acp.budget.quota import QuotaCounter
from acp.exceptions import QuotaExceededError


def enforce_quota(quota: QuotaCounter, principal: str, now: float, cost: float = 1.0) -> None:
    """Spend ``cost`` of ``principal``'s quota, or raise.

    Returns ``None`` when the spend fits within the window's limit. Raises
    ``QuotaExceededError`` when it would exceed it, with the seconds until the
    window resets in ``details['retry_after']``.
    """
    if quota.check(principal, now, cost):
        return
    raise QuotaExceededError(
        "quota exceeded for the current window",
        details={"retry_after": quota.retry_after(now)},
    )
