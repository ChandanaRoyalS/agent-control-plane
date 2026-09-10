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


def test_the_bucket_map_is_bounded() -> None:
    """**Unbounded growth an authenticated caller chooses the size of.**

    One entry per principal, created on first sight — and created by
    `retry_after` and `remaining` too, which only read. An identity provider
    that mints distinct subjects, or simply a tenant with many users, grew this
    without limit. The result cache and the credential cache were both bounded
    for exactly this reason; this was not (ADR 0063).
    """
    limiter = RateLimiter(capacity=5, refill_per_second=1, max_principals=64)

    for index in range(1_000):
        limiter.check(f"subject-{index}", now=0.0)

    assert len(limiter._buckets) <= 64  # noqa: SLF001


def test_reading_a_limit_cannot_grow_the_map_without_bound() -> None:
    """`retry_after` and `remaining` create a bucket as a side effect of being
    asked, which makes an unauthenticated-looking read a write."""
    limiter = RateLimiter(capacity=5, refill_per_second=1, max_principals=32)

    for index in range(500):
        limiter.remaining(f"subject-{index}")
        limiter.retry_after(f"subject-{index}")

    assert len(limiter._buckets) <= 32  # noqa: SLF001


def test_the_most_recently_used_principal_survives_eviction() -> None:
    """Least-recently-used, not first-seen: the principal still calling is the
    one whose bucket state is worth keeping, and evicting a bucket refunds
    whoever held it."""
    limiter = RateLimiter(capacity=5, refill_per_second=1, max_principals=8)
    limiter.check("steady", now=0.0)

    for index in range(4):
        limiter.check(f"other-{index}", now=0.0)
        limiter.check("steady", now=0.0)

    assert "steady" in limiter._buckets  # noqa: SLF001
