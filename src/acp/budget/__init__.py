"""Budget controls: keep an agent's spending bounded (Phase 4).

The first control is rate limiting — a token bucket per principal, so a runaway
or compromised agent draws from a bucket that refills at a fixed rate rather than
calling without bound. Quotas, cost accounting, and result caching join here as
the phase lands.
"""

from acp.budget.enforce import enforce_rate_limit
from acp.budget.ratelimit import RateLimiter, TokenBucket

__all__ = ["RateLimiter", "TokenBucket", "enforce_rate_limit"]
