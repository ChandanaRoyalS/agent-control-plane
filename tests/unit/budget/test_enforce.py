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


# --- cost-weighted enforcement (task 39) ---


def test_a_costly_call_debits_more_than_one() -> None:
    """A call costing 5 drains a 10-capacity bucket in two, not ten."""
    limiter = RateLimiter(capacity=10, refill_per_second=0.0)
    enforce_rate_limit(limiter, "alice", T0, cost=5.0)
    enforce_rate_limit(limiter, "alice", T0, cost=5.0)
    with pytest.raises(RateLimitExceededError):
        enforce_rate_limit(limiter, "alice", T0, cost=5.0)


def test_a_free_call_never_exhausts_the_budget() -> None:
    """A zero-cost call draws nothing, so it always passes."""
    limiter = RateLimiter(capacity=1, refill_per_second=0.0)
    for _ in range(100):
        enforce_rate_limit(limiter, "alice", T0, cost=0.0)


def test_the_default_cost_is_one() -> None:
    """Called without a cost, enforcement charges one — task 38 behaviour."""
    limiter = RateLimiter(capacity=1, refill_per_second=0.0)
    enforce_rate_limit(limiter, "alice", T0)
    with pytest.raises(RateLimitExceededError):
        enforce_rate_limit(limiter, "alice", T0)


# ---------------------------------------------------------------------------
# Remaining allowance — the other half of an agent-readable refusal
# ---------------------------------------------------------------------------


def test_a_refusal_says_how_much_is_left_as_well_as_when() -> None:
    """`retry_after` tells an agent *when* it may try again. `remaining` tells
    it *how much* it may still do, which is the difference between backing off
    blindly and planning: given three units and five queued calls, an agent that
    knows the number can choose which three."""
    limiter = RateLimiter(capacity=2.0, refill_per_second=1.0)
    assert limiter.check("alice", 0.0, 2.0)

    with pytest.raises(RateLimitExceededError) as raised:
        enforce_rate_limit(limiter, "alice", 0.0, 1.0)

    details = raised.value.details
    assert details["remaining"] == 0.0
    assert details["limit"] == 2.0
    assert details["retry_after"] > 0


def test_remaining_is_the_scale_as_well_as_the_number() -> None:
    """ "2 left" means something different out of 5 than out of 500, so the
    capacity travels with it."""
    limiter = RateLimiter(capacity=10.0, refill_per_second=1.0)
    limiter.check("alice", 0.0, 4.0)

    assert limiter.remaining("alice") == 6.0
    assert limiter.capacity == 10.0


def test_an_untouched_bucket_reports_its_full_capacity() -> None:
    """A bucket initialises full on first take, so reading the pre-initialisation
    zero would tell a caller who has done nothing that it has nothing left. The
    same correction `retry_after` already made."""
    limiter = RateLimiter(capacity=5.0, refill_per_second=1.0)

    assert limiter.remaining("never-seen") == 5.0
    assert limiter.retry_after("never-seen") == 0.0


def test_remaining_refills_with_time() -> None:
    limiter = RateLimiter(capacity=4.0, refill_per_second=2.0)
    limiter.check("alice", 0.0, 4.0)
    assert limiter.remaining("alice") == 0.0

    limiter.check("alice", 1.0, 0.0)

    assert limiter.remaining("alice") == 2.0
