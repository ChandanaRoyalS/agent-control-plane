"""Turn a rate-limiter decision into a refused call, or let it pass.

The counterpart to ``policy.enforce_call``: a pure boundary the request path
calls in one place. The limiter decides whether the principal is within budget;
this raises ``RateLimitExceededError`` when they are not, carrying both halves
of what a refused agent needs: how long until it may retry, and how much
allowance is left when it does.
"""

from __future__ import annotations

from acp.budget.ratelimit import RateLimiter
from acp.exceptions import RateLimitExceededError


def enforce_rate_limit(limiter: RateLimiter, principal: str, now: float, cost: float = 1.0) -> None:
    """Consume ``cost`` units of ``principal``'s budget, or raise.

    Returns ``None`` when the call is within budget. Raises
    ``RateLimitExceededError`` when the bucket is empty, carrying two numbers:

    ``retry_after`` — seconds until a token returns. Tells the agent *when*.

    ``remaining`` — units available right now, and ``limit``, the bucket's
    capacity. Tells the agent *how much*, which is the difference between one
    that backs off blindly and one that plans: given three units and five
    queued calls, an agent that knows the number can choose which three.

    All three are safe to expose. They describe only the limit the caller is
    already hitting — nothing about other callers, and nothing about anyone
    else's budget.
    """
    if limiter.check(principal, now, cost):
        return
    raise RateLimitExceededError(
        "rate limit exceeded; slow down",
        details={
            "retry_after": limiter.retry_after(principal, cost),
            "remaining": limiter.remaining(principal),
            "limit": limiter.capacity,
        },
    )
