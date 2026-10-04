"""Unit tests for the token-bucket rate limiter.

Time is injected, so these tests are exact: they advance ``now`` by hand and
assert the precise transition, without a real clock or any sleeping.
"""

from __future__ import annotations

import math

from acp.budget import RateLimiter, TokenBucket

T0 = 1000.0


def test_a_fresh_bucket_starts_full() -> None:
    """First sight fills the bucket, so a new principal may burst to capacity."""
    rl = RateLimiter(capacity=3, refill_per_second=1.0)
    assert [rl.check("alice", T0) for _ in range(3)] == [True, True, True]


def test_the_bucket_blocks_once_empty() -> None:
    rl = RateLimiter(capacity=2, refill_per_second=1.0)
    assert rl.check("alice", T0)
    assert rl.check("alice", T0)
    assert rl.check("alice", T0) is False


def test_it_refills_at_the_configured_rate() -> None:
    """One token per second: after one second, exactly one call is affordable."""
    rl = RateLimiter(capacity=1, refill_per_second=1.0)
    assert rl.check("alice", T0)
    assert rl.check("alice", T0) is False
    assert rl.check("alice", T0 + 1.0)
    assert rl.check("alice", T0 + 1.0) is False


def test_refill_is_capped_at_capacity() -> None:
    """Idle time does not accrue unbounded tokens — the burst ceiling holds."""
    rl = RateLimiter(capacity=3, refill_per_second=1.0)
    assert rl.check("alice", T0)  # spend one, 2 left
    # idle a long time, then one call: should refill to 3, minus the 1 taken = 2
    assert rl.check("alice", T0 + 1000.0)
    assert rl._bucket("alice").tokens == 2.0


def test_principals_have_independent_buckets() -> None:
    rl = RateLimiter(capacity=1, refill_per_second=1.0)
    assert rl.check("alice", T0)
    assert rl.check("bob", T0)  # bob's bucket is untouched by alice
    assert rl.check("alice", T0) is False


def test_retry_after_is_zero_when_a_token_is_available() -> None:
    rl = RateLimiter(capacity=2, refill_per_second=1.0)
    assert rl.retry_after("alice") == 0.0


def test_retry_after_reflects_the_shortfall_and_rate() -> None:
    """Empty bucket at 2 tokens/sec: one token is half a second away."""
    rl = RateLimiter(capacity=1, refill_per_second=2.0)
    assert rl.check("alice", T0)
    assert rl.check("alice", T0) is False
    assert rl.retry_after("alice") == 0.5


def test_a_zero_refill_rate_never_recovers() -> None:
    """Capacity but no refill: a one-shot budget. Once spent, retry is forever."""
    rl = RateLimiter(capacity=1, refill_per_second=0.0)
    assert rl.check("alice", T0)
    assert rl.check("alice", T0) is False
    assert math.isinf(rl.retry_after("alice"))


def test_a_backwards_clock_never_removes_tokens() -> None:
    """A clock that goes back adds nothing but must not debit — defensive, since
    a monotonic clock should never move backwards."""
    bucket = TokenBucket(capacity=3, refill_per_second=1.0)
    assert bucket.take(T0)
    before = bucket.tokens
    assert bucket.take(T0 - 5.0)  # earlier "now"
    assert bucket.tokens == before - 1.0  # spent one, refilled none


def test_cost_greater_than_one_is_debited() -> None:
    """A call may cost more than one token — the hook for cost accounting later."""
    rl = RateLimiter(capacity=5, refill_per_second=1.0)
    assert rl.check("alice", T0, cost=3.0)
    assert rl.check("alice", T0, cost=3.0) is False  # only 2 left
    assert rl.check("alice", T0, cost=2.0)


# ---------------------------------------------------------------------------
# Per-principal state is bounded, and asking creates nothing
# ---------------------------------------------------------------------------


def test_the_limiter_forgets_the_least_recently_charged_principal() -> None:
    """An authenticated caller chooses the keys: a tenant's IdP minting
    per-session subjects would grow the dict without limit. The result cache
    was bounded for exactly this reason; the budgets were not."""
    limiter = RateLimiter(capacity=5, refill_per_second=0, max_principals=3)
    for principal in ("a", "b", "c"):
        assert limiter.check(principal, now=0.0)
    assert limiter.check("a", now=1.0)  # a is now the most recent
    assert limiter.check("d", now=2.0)  # evicts b, the least recent

    assert limiter.remaining("b") == 5, "forgotten: a fresh, full bucket on return"
    assert limiter.remaining("a") == 3
    assert limiter.remaining("d") == 4


def test_asking_about_a_stranger_creates_no_bucket() -> None:
    """`retry_after` and `remaining` used to create a bucket for a principal
    never charged — so a stream of distinct names in refusals' detail fields
    could fill the table without a single successful call."""
    limiter = RateLimiter(capacity=5, refill_per_second=1, max_principals=3)

    assert limiter.retry_after("nobody") == 0.0
    assert limiter.remaining("nobody") == 5
    assert len(limiter._buckets) == 0


def test_affords_does_not_debit() -> None:
    limiter = RateLimiter(capacity=2, refill_per_second=0)
    assert limiter.affords("a", now=0.0, cost=2)
    assert limiter.affords("a", now=0.0, cost=2), "still affordable: nothing was spent"
    assert not limiter.affords("a", now=0.0, cost=3)
    assert limiter.remaining("a") == 2
