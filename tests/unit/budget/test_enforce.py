"""Unit tests for rate-limit enforcement.

``enforce_rate_limit`` is the boundary the request path calls: pass within
budget, raise ``RateLimitExceededError`` when over it, carrying a retry hint.
"""

from __future__ import annotations

import pytest

from acp.budget import RateLimiter, enforce_rate_limit
from acp.exceptions import RateLimitExceededError

T0 = 1000.0


def test_within_budget_passes_silently() -> None:
    limiter = RateLimiter(capacity=2, refill_per_second=1.0)
    enforce_rate_limit(limiter, "alice", T0)  # does not raise


def test_over_budget_raises() -> None:
    limiter = RateLimiter(capacity=1, refill_per_second=1.0)
    enforce_rate_limit(limiter, "alice", T0)
    with pytest.raises(RateLimitExceededError):
        enforce_rate_limit(limiter, "alice", T0)


def test_the_error_is_recoverable() -> None:
    """A rate-limit error tells the agent to wait and retry, not to stop."""
    limiter = RateLimiter(capacity=1, refill_per_second=1.0)
    enforce_rate_limit(limiter, "alice", T0)
    with pytest.raises(RateLimitExceededError) as exc:
        enforce_rate_limit(limiter, "alice", T0)
    assert exc.value.recoverable is True


def test_the_error_carries_a_retry_after_hint() -> None:
    limiter = RateLimiter(capacity=1, refill_per_second=2.0)
    enforce_rate_limit(limiter, "alice", T0)
    with pytest.raises(RateLimitExceededError) as exc:
        enforce_rate_limit(limiter, "alice", T0)
    assert exc.value.details["retry_after"] == 0.5


def test_the_budget_recovers_with_time() -> None:
    """The identical call succeeds once the bucket has refilled — the defining
    difference from a policy denial."""
    limiter = RateLimiter(capacity=1, refill_per_second=1.0)
    enforce_rate_limit(limiter, "alice", T0)
    with pytest.raises(RateLimitExceededError):
        enforce_rate_limit(limiter, "alice", T0)
    enforce_rate_limit(limiter, "alice", T0 + 1.0)  # refilled, passes


def test_limits_are_per_principal() -> None:
    limiter = RateLimiter(capacity=1, refill_per_second=1.0)
    enforce_rate_limit(limiter, "alice", T0)
    enforce_rate_limit(limiter, "bob", T0)  # bob unaffected by alice
    with pytest.raises(RateLimitExceededError):
        enforce_rate_limit(limiter, "alice", T0)
