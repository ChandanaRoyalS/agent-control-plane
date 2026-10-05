"""The shared budgets: one bucket and one tally per payer, for the whole fleet.

The in-memory limiter and quota are the specification. The Redis keeper must
answer every case they answer identically — same refusal, same three numbers —
and the contract tests below run each case against both so that the Lua and
the Python cannot drift apart unnoticed. What only a shared keeper can do is
tested on its own: two replicas drain one bucket, a bucket nobody holds is a
full one, and the check-both-then-debit-both ordering holds when the two
checks are on a server rather than in a function.

`fakeredis` runs the script through `lupa`, so these need no Redis.
"""

from __future__ import annotations

from collections.abc import Callable

import fakeredis
import pytest
from fakeredis import aioredis

from acp.budget.charge import Budgets, LocalBudgets
from acp.budget.quota import QuotaCounter
from acp.budget.ratelimit import RateLimiter
from acp.budget.redis_store import QUOTA_PREFIX, RedisBudgets, quota_key, rate_key
from acp.exceptions import ConfigurationError, QuotaExceededError, RateLimitExceededError

T0 = 1000.0
CAPACITY = 3.0
REFILL = 1.0
LIMIT = 5.0
WINDOW = 100.0

Factory = Callable[[], Budgets]


def local() -> Budgets:
    return LocalBudgets(
        RateLimiter(capacity=CAPACITY, refill_per_second=REFILL),
        QuotaCounter(limit=LIMIT, window_seconds=WINDOW),
    )


def shared(server: fakeredis.FakeServer | None = None) -> RedisBudgets:
    return RedisBudgets(
        aioredis.FakeRedis(server=server or fakeredis.FakeServer()),
        capacity=CAPACITY,
        refill_per_second=REFILL,
        limit=LIMIT,
        window_seconds=WINDOW,
    )


@pytest.fixture(params=[local, shared], ids=["memory", "redis"])
def budgets(request: pytest.FixtureRequest) -> Budgets:
    factory: Factory = request.param
    return factory()


async def charge(b: Budgets, cost: float = 1.0, *, at: float = T0, payer: str = "alice") -> None:
    # The same reading for both clocks: the in-memory keeper refills on the
    # first and windows on the second, the shared one uses the second for both.
    await b.charge(payer, cost, mono=at, wall=at)


# ---------------------------------------------------------------------------
# The contract both keepers honour
# ---------------------------------------------------------------------------


async def test_a_fresh_payer_may_burst_to_capacity_and_no_further(budgets: Budgets) -> None:
    for _ in range(int(CAPACITY)):
        await charge(budgets)

    with pytest.raises(RateLimitExceededError) as refused:
        await charge(budgets)

    assert refused.value.details == {"retry_after": 1.0, "remaining": 0.0, "limit": CAPACITY}


async def test_the_bucket_refills_at_the_rate(budgets: Budgets) -> None:
    for _ in range(int(CAPACITY)):
        await charge(budgets)

    await charge(budgets, at=T0 + 1.0)  # one token back
    with pytest.raises(RateLimitExceededError):
        await charge(budgets, at=T0 + 1.0)


async def test_the_bucket_does_not_overfill(budgets: Budgets) -> None:
    await charge(budgets)

    for _ in range(int(CAPACITY)):
        await charge(budgets, at=T0 + 1000.0)
    with pytest.raises(RateLimitExceededError):
        await charge(budgets, at=T0 + 1000.0)


async def test_a_backwards_clock_removes_nothing(budgets: Budgets) -> None:
    await charge(budgets)

    await charge(budgets, at=T0 - 50.0)
    await charge(budgets, at=T0 - 50.0)
    with pytest.raises(RateLimitExceededError):
        await charge(budgets, at=T0 - 50.0)


async def test_the_quota_refuses_the_call_that_would_exceed_the_window(budgets: Budgets) -> None:
    # Spread the calls so the bucket never refuses first.
    for i in range(int(LIMIT)):
        await charge(budgets, at=T0 + i * 2.0)

    with pytest.raises(QuotaExceededError) as refused:
        await charge(budgets, at=T0 + 20.0)

    assert refused.value.details == {
        "retry_after": pytest.approx(80.0),
        "remaining": 0.0,
        "limit": LIMIT,
    }


async def test_the_quota_resets_at_the_window_boundary(budgets: Budgets) -> None:
    for i in range(int(LIMIT)):
        await charge(budgets, at=T0 + i * 2.0)

    await charge(budgets, at=T0 + WINDOW)  # the next window


async def test_a_quota_refusal_leaves_the_rate_tokens_unspent(budgets: Budgets) -> None:
    """ADR 0044 §3. The call the quota refuses must not have drained the
    bucket on its way out — otherwise a payer at their quota ceiling is also
    stripped of burst for calls that never ran."""
    for i in range(int(LIMIT)):
        await charge(budgets, at=T0 + i * 10.0)
    with pytest.raises(QuotaExceededError):
        await charge(budgets, at=T0 + 50.0)

    # Still refused by the quota, not the bucket: the bucket is full.
    with pytest.raises(QuotaExceededError):
        await charge(budgets, at=T0 + 50.0)


async def test_cost_is_charged_to_both_budgets(budgets: Budgets) -> None:
    await charge(budgets, 2.0)

    with pytest.raises(RateLimitExceededError) as refused:
        await charge(budgets, 2.0)
    assert refused.value.details["remaining"] == 1.0

    # And the quota saw the two as well: three more units reach the limit,
    # and the half-unit after that is refused by the quota, not the bucket.
    await charge(budgets, 3.0, at=T0 + WINDOW - 1.0)  # bucket full again, same window
    with pytest.raises(QuotaExceededError) as over:
        await charge(budgets, 0.5, at=T0 + WINDOW - 0.5)
    assert over.value.details["remaining"] == 0.0


async def test_the_quota_tells_a_partial_remainder(budgets: Budgets) -> None:
    """The case `enforce_quota` names: refused with something left, because
    the call asked for more than what is left."""
    await charge(budgets, 3.0)

    with pytest.raises(QuotaExceededError) as refused:
        await charge(budgets, 3.0, at=T0 + 10.0)

    assert refused.value.details["remaining"] == 2.0


async def test_payers_do_not_share_a_budget(budgets: Budgets) -> None:
    for _ in range(int(CAPACITY)):
        await charge(budgets, payer="alice")

    await charge(budgets, payer="tenant-b:alice")


# ---------------------------------------------------------------------------
# What only a shared keeper does
# ---------------------------------------------------------------------------


async def test_two_replicas_drain_one_bucket() -> None:
    """The bug (threat model 6.6): per-process buckets multiply the burst by
    the replica count. Here two gateways share one, and the payer gets one."""
    server = fakeredis.FakeServer()
    a, b = shared(server), shared(server)

    await charge(a)
    await charge(b)
    await charge(a)

    with pytest.raises(RateLimitExceededError):
        await charge(b)


async def test_two_replicas_fill_one_window() -> None:
    server = fakeredis.FakeServer()
    a, b = shared(server), shared(server)
    for i in range(int(LIMIT)):
        await charge(a if i % 2 else b, at=T0 + i * 2.0)

    with pytest.raises(QuotaExceededError):
        await charge(a, at=T0 + 20.0)


async def test_a_bucket_nobody_holds_is_a_full_one() -> None:
    """The store's bound is time: the key expires when the bucket would be
    full, and a missing key reads as capacity. Deleting it is the same as
    waiting it out."""
    a = RedisBudgets(
        aioredis.FakeRedis(server=fakeredis.FakeServer()),
        capacity=CAPACITY,
        refill_per_second=REFILL,
        limit=None,
    )
    for _ in range(int(CAPACITY)):
        await charge(a)
    await a._redis.delete(rate_key("alice"))

    for _ in range(int(CAPACITY)):
        await charge(a)


async def test_the_bucket_key_expires_when_the_bucket_would_be_full() -> None:
    a = shared()
    for _ in range(int(CAPACITY)):
        await charge(a)

    ttl = await a._redis.ttl(rate_key("alice"))

    assert ttl == pytest.approx(CAPACITY / REFILL, abs=1)


async def test_the_tally_key_names_the_window_and_expires_with_it() -> None:
    a = shared()
    await charge(a, at=T0 + 30.0)

    key = quota_key("alice", T0 + 30.0, WINDOW)
    assert key == f"{QUOTA_PREFIX}alice:10"
    assert await a._redis.ttl(key) == pytest.approx(70.0, abs=1)


async def test_a_rate_limit_alone_charges_no_quota() -> None:
    a = RedisBudgets(
        aioredis.FakeRedis(server=fakeredis.FakeServer()),
        capacity=CAPACITY,
        refill_per_second=REFILL,
        limit=None,
    )
    for i in range(20):
        await charge(a, at=T0 + i * 5.0)

    assert await a._redis.keys(f"{QUOTA_PREFIX}*") == []


async def test_a_quota_alone_charges_no_bucket() -> None:
    a = RedisBudgets(
        aioredis.FakeRedis(server=fakeredis.FakeServer()),
        capacity=None,
        limit=LIMIT,
        window_seconds=WINDOW,
    )
    for _ in range(int(LIMIT)):
        await charge(a)  # faster than any bucket would allow

    with pytest.raises(QuotaExceededError):
        await charge(a)
    assert await a._redis.exists(rate_key("alice")) == 0


def test_a_keeper_with_nothing_to_charge_is_refused() -> None:
    with pytest.raises(ValueError, match="nothing to charge"):
        RedisBudgets(aioredis.FakeRedis(server=fakeredis.FakeServer()), capacity=None, limit=None)


async def test_a_bucket_that_never_refills_reports_an_unbounded_wait() -> None:
    a = RedisBudgets(
        aioredis.FakeRedis(server=fakeredis.FakeServer()),
        capacity=1.0,
        refill_per_second=0.0,
        limit=None,
    )
    await charge(a)

    with pytest.raises(RateLimitExceededError) as refused:
        await charge(a)

    assert refused.value.details["retry_after"] == float("inf")


async def test_an_unreachable_redis_is_a_configuration_error_at_ping() -> None:
    server = fakeredis.FakeServer()
    server.connected = False

    with pytest.raises(ConfigurationError, match="budget store"):
        await shared(server).ping()


async def test_a_reachable_redis_pings_quietly() -> None:
    await shared().ping()
