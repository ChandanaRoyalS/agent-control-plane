"""Turn a rate-limiter decision into a refused call, or let it pass.

Like ``policy.enforce_call``, a pure boundary called in one place on the request path.
"""

from __future__ import annotations

from acp.budget.ratelimit import RateLimiter
from acp.exceptions import RateLimitExceededError


def enforce_rate_limit(
    limiter: RateLimiter, principal: str, now: float, cost: float = 1.0, *, debit: bool = True
) -> None:
    """Consume ``cost`` units of ``principal``'s budget, or raise.

    With ``debit=False`` only checks affordability.

    Raises:
        RateLimitExceededError: with ``retry_after`` (seconds until a token returns),
            ``remaining`` and ``limit`` (bucket capacity). These describe only the
            caller's own budget, so they are safe to expose.
    """
    if (limiter.check if debit else limiter.affords)(principal, now, cost):
        return
    raise RateLimitExceededError(
        "rate limit exceeded; slow down",
        details={
            "retry_after": limiter.retry_after(principal, cost),
            "remaining": limiter.remaining(principal),
            "limit": limiter.capacity,
        },
    )
