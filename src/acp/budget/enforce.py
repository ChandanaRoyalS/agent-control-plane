"""Turn a rate-limiter decision into a refused call, or let it pass.

The counterpart to ``policy.enforce_call``: a pure boundary the request path
calls in one place. The limiter decides whether the principal is within budget;
this raises ``RateLimitExceededError`` when they are not, carrying a
``retry_after`` hint so a well-behaved agent knows to wait rather than hammer.
"""

from __future__ import annotations

from acp.budget.ratelimit import RateLimiter
from acp.exceptions import RateLimitExceededError


def enforce_rate_limit(limiter: RateLimiter, principal: str, now: float) -> None:
    """Consume one unit of ``principal``'s budget, or raise.

    Returns ``None`` when the call is within budget. Raises
    ``RateLimitExceededError`` when the bucket is empty, with the seconds until a
    token returns in ``details['retry_after']`` — a hint the caller may use to
    back off, safe to expose because it describes only the limit already being
    hit.
    """
    if limiter.check(principal, now):
        return
    raise RateLimitExceededError(
        "rate limit exceeded; slow down",
        details={"retry_after": limiter.retry_after(principal)},
    )
