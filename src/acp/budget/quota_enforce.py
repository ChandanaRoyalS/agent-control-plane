"""Turn a quota decision into a refused call, or let it pass.

The quota counterpart to ``enforce_rate_limit``: a pure boundary the request
path calls in one place. The quota decides whether the principal has budget left
in the current window; this raises ``QuotaExceededError`` when they do not,
carrying both halves of what a refused agent needs: when the window resets, and
how much of the allowance is left when it does.
"""

from __future__ import annotations

from acp.budget.quota import QuotaCounter
from acp.exceptions import QuotaExceededError


def enforce_quota(quota: QuotaCounter, principal: str, now: float, cost: float = 1.0) -> None:
    """Spend ``cost`` of ``principal``'s quota, or raise.

    Returns ``None`` when the spend fits within the window's limit. Raises
    ``QuotaExceededError`` when it would exceed it, carrying the same three
    fields as the rate-limit refusal — ``retry_after``, ``remaining`` and
    ``limit`` — spelled identically on purpose. A refused agent should not have
    to work out *which* budget stopped it before it can read the answer.

    ``remaining`` is usually non-zero here where it is zero for a rate limit: a
    quota refuses a call that would *exceed* the window's limit, so a caller
    with two units left asking for a call that costs ten is refused with two
    still available. That is exactly the case where the number earns its place —
    the agent can spend the two on something cheaper instead of waiting out the
    window.
    """
    if quota.check(principal, now, cost):
        return
    raise QuotaExceededError(
        "quota exceeded for the current window",
        details={
            "retry_after": quota.retry_after(now),
            "remaining": quota.remaining(principal, now),
            "limit": quota.limit,
        },
    )
