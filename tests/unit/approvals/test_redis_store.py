"""The shared store: the same four operations, now across replicas.

Everything the in-memory store promises, the Redis store must promise through a
network — and two things more that only matter once there is more than one
gateway. A decision made on one replica is the decision a retry on another
spends. And an approved token is spent exactly once, however many retries
carry it at the same moment: that is a compare-and-set in the store, because
no amount of care at the call site can make "read, then write" atomic across
two processes.

The tests run against `fakeredis`, which implements `WATCH`/`MULTI` and TTLs
in-process. Two store instances on one fake server are two replicas on one
Redis; that is the scenario the whole module exists for.
"""

from __future__ import annotations

from collections.abc import Callable

import anyio
import fakeredis
import pytest
from fakeredis import aioredis

from acp.approvals import redis_store as redis_store_module
from acp.approvals.record import ApprovalRequest, State, request_for
from acp.approvals.redis_store import (
    APPROVAL_STORE_SCHEMES,
    GRACE_SECONDS,
    PENDING_SET,
    RedisApprovalStore,
    decode,
    encode,
    key_for,
)
from acp.approvals.store import ApprovalStore, InMemoryApprovalStore
from acp.exceptions import ConfigurationError

NOW = 1000.0
TTL = 300.0


def a_request(index: int = 0, *, subject: str = "alice", now: float = NOW) -> ApprovalRequest:
    request = request_for(
        tenant=None,
        subject=subject,
        actor=None,
        tool="crm__delete_record",
        arguments={"n": index},
        rule="approve-deletes",
        now=now,
        ttl=TTL,
    )
    assert request is not None
    return request


def redis_pair() -> tuple[RedisApprovalStore, RedisApprovalStore, fakeredis.FakeServer]:
    """Two replicas' stores on one Redis."""
    server = fakeredis.FakeServer()
    return (
        RedisApprovalStore(aioredis.FakeRedis(server=server)),
        RedisApprovalStore(aioredis.FakeRedis(server=server)),
        server,
    )


# ---------------------------------------------------------------------------
# The contract both stores keep
# ---------------------------------------------------------------------------

StoreFactory = Callable[[], ApprovalStore]


def memory_store() -> ApprovalStore:
    return InMemoryApprovalStore()


def redis_store() -> ApprovalStore:
    return redis_pair()[0]


@pytest.fixture(params=[memory_store, redis_store], ids=["memory", "redis"])
def store(request: pytest.FixtureRequest) -> ApprovalStore:
    factory: StoreFactory = request.param
    return factory()


async def test_a_created_request_reads_back_equal(store: ApprovalStore) -> None:
    request = a_request()
    await store.create(request)

    assert await store.get(request.token) == request


async def test_an_unknown_token_is_absent(store: ApprovalStore) -> None:
    assert await store.get("nope") is None
    assert await store.decide("nope", approved=True) is None
    assert await store.consume("nope") is False


async def test_a_decision_is_recorded_once(store: ApprovalStore) -> None:
    request = a_request()
    await store.create(request)

    first = await store.decide(request.token, approved=False, reason="no")
    second = await store.decide(request.token, approved=True)

    assert first is not None
    assert first.state is State.DENIED
    assert second is not None
    assert second.state is State.DENIED, "the first answer stands"


async def test_only_an_approved_request_can_be_spent(store: ApprovalStore) -> None:
    """`consume` is not "mark it used"; it is "spend the approval". A pending
    or denied record has no approval in it to spend."""
    pending = a_request(0)
    denied = a_request(1)
    await store.create(pending)
    await store.create(denied)
    await store.decide(denied.token, approved=False)

    assert await store.consume(pending.token) is False
    assert await store.consume(denied.token) is False
    assert (await store.get(pending.token)).state is State.PENDING  # type: ignore[union-attr]


async def test_an_approval_is_spent_exactly_once(store: ApprovalStore) -> None:
    request = a_request()
    await store.create(request)
    await store.decide(request.token, approved=True)

    assert await store.consume(request.token) is True
    assert await store.consume(request.token) is False
    held = await store.get(request.token)
    assert held is not None
    assert held.state is State.CONSUMED


async def test_a_spent_request_cannot_be_re_approved(store: ApprovalStore) -> None:
    request = a_request()
    await store.create(request)
    await store.decide(request.token, approved=True)
    await store.consume(request.token)

    again = await store.decide(request.token, approved=True)

    assert again is not None
    assert again.state is State.CONSUMED


# ---------------------------------------------------------------------------
# What only a shared store can do
# ---------------------------------------------------------------------------


async def test_a_request_held_on_one_replica_is_decided_on_another_and_spent_on_a_third() -> None:
    """The bug the module fixes (ADR 0066): a caller told to wait by replica A
    retries against replica B, after an operator answered on replica C."""
    a, b, server = redis_pair()
    c = RedisApprovalStore(aioredis.FakeRedis(server=server))
    request = a_request()
    await a.create(request)

    decided = await c.decide(request.token, approved=True, reason="looks fine")

    assert decided is not None
    assert decided.state is State.APPROVED
    assert (await b.get(request.token)) == decided
    assert await b.consume(request.token) is True
    assert (await a.get(request.token)).state is State.CONSUMED  # type: ignore[union-attr]


async def test_two_operators_answering_at_once_resolve_to_one_answer() -> None:
    """Both read PENDING; both write. Exactly one write lands, and the other
    operator is shown the answer that did."""
    a, b, _ = redis_pair()
    request = a_request()
    await a.create(request)

    results: list[ApprovalRequest | None] = []

    async def answer(store: RedisApprovalStore, approved: bool) -> None:
        results.append(await store.decide(request.token, approved=approved))

    async with anyio.create_task_group() as group:
        group.start_soon(answer, a, True)
        group.start_soon(answer, b, False)

    states = {r.state for r in results if r is not None}
    assert len(results) == 2
    assert len(states) == 1, "the two operators saw two different answers"
    final = await a.get(request.token)
    assert final is not None
    assert final.state in states


async def test_two_retries_spending_one_approval_let_exactly_one_proceed() -> None:
    """The double-spend. Same approved token, two replicas, same instant."""
    a, b, _ = redis_pair()
    request = a_request()
    await a.create(request)
    await a.decide(request.token, approved=True)

    outcomes: list[bool] = []

    async def spend(store: RedisApprovalStore) -> None:
        outcomes.append(await store.consume(request.token))

    async with anyio.create_task_group() as group:
        group.start_soon(spend, a)
        group.start_soon(spend, b)

    assert sorted(outcomes) == [False, True]


async def test_the_compare_and_set_notices_a_write_underneath_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry path of `_transition`, driven rather than hoped for. `decode`
    runs inside the WATCH window — after the read, before MULTI — so a write
    from there is a write from another replica at the worst moment. The first
    attempt must be thrown away, and the second must see the new state."""
    a, b, server = redis_pair()
    request = a_request()
    await a.create(request)
    other_replica = fakeredis.FakeRedis(server=server)
    real_decode = redis_store_module.decode
    stolen = False

    def decode_then_steal(raw: bytes | str) -> ApprovalRequest:
        nonlocal stolen
        if not stolen:
            stolen = True
            other_replica.set(key_for(request.token), encode(request.decided(approved=False)))
        return real_decode(raw)

    monkeypatch.setattr(redis_store_module, "decode", decode_then_steal)

    result = await a.decide(request.token, approved=True)

    assert result is not None
    assert result.state is State.DENIED, "the stolen write won; ours saw it on retry"
    assert (await b.get(request.token)).state is State.DENIED  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Time is the bound, not a count
# ---------------------------------------------------------------------------


async def test_a_record_outlives_its_expiry_by_the_grace_and_no_longer() -> None:
    """Expired is computed from the record (ADR 0048), so the record must stay
    readable past its own expiry — a late retry gets "expired", not "no such
    request". The grace is how long; Redis forgets it after."""
    a, _, _ = redis_pair()
    request = a_request()
    await a.create(request)

    ttl = await a._redis.ttl(key_for(request.token))

    assert ttl == pytest.approx(TTL + GRACE_SECONDS, abs=2)


async def test_a_decision_keeps_the_records_remaining_life() -> None:
    """A transition must not reset the clock. Re-writing with a fresh TTL would
    let a decided record outlive the pending one it came from."""
    a, _, _ = redis_pair()
    request = a_request()
    await a.create(request)
    await a._redis.expire(key_for(request.token), 42)

    await a.decide(request.token, approved=True)

    assert await a._redis.ttl(key_for(request.token)) <= 42


async def test_there_is_no_eviction_and_no_cap() -> None:
    """The in-memory store evicts at `max_pending`. Here a flood costs the
    flooder re-asks and costs Redis one TTL of memory; nobody else's request
    is pushed out to make room."""
    a, _, _ = redis_pair()
    requests = [a_request(i, subject=f"agent-{i}") for i in range(300)]
    for request in requests:
        await a.create(request)

    assert len(await a.pending()) == 300
    for request in requests:
        assert await a.get(request.token) is not None


async def test_a_second_create_for_the_same_token_does_not_overwrite() -> None:
    a, _, _ = redis_pair()
    request = a_request()
    await a.create(request)
    await a.decide(request.token, approved=True)

    await a.create(request)  # a bug upstream, not a reset

    assert (await a.get(request.token)).state is State.APPROVED  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Listing for the operator
# ---------------------------------------------------------------------------


async def test_pending_lists_only_what_still_awaits_a_person_oldest_first() -> None:
    a, b, _ = redis_pair()
    second = a_request(1, now=NOW + 10)
    first = a_request(0, now=NOW)
    done = a_request(2, now=NOW + 5)
    for request in (second, first, done):
        await a.create(request)
    await b.decide(done.token, approved=True)

    listed = await b.pending()

    assert [r.token for r in listed] == [first.token, second.token]


async def test_pending_prunes_members_whose_record_redis_forgot() -> None:
    """The set and the records expire independently. A member with no record
    is one Redis has already forgotten; the listing drops it from the set
    rather than listing a ghost or failing."""
    a, _, _ = redis_pair()
    request = a_request()
    await a.create(request)
    await a._redis.delete(key_for(request.token))

    assert await a.pending() == ()
    assert await a._redis.smembers(PENDING_SET) == set()


# ---------------------------------------------------------------------------
# Starting, and refusing to
# ---------------------------------------------------------------------------


async def test_an_unreachable_redis_is_a_configuration_error_at_ping() -> None:
    server = fakeredis.FakeServer()
    server.connected = False
    store = RedisApprovalStore(aioredis.FakeRedis(server=server))

    with pytest.raises(ConfigurationError, match="unreachable"):
        await store.ping()


async def test_a_reachable_redis_pings_quietly() -> None:
    a, _, _ = redis_pair()
    await a.ping()


def test_from_url_accepts_each_scheme_the_setting_allows() -> None:
    for scheme in APPROVAL_STORE_SCHEMES:
        store = RedisApprovalStore.from_url(f"{scheme}example.test/0")
        assert isinstance(store, RedisApprovalStore)


# ---------------------------------------------------------------------------
# The wire format
# ---------------------------------------------------------------------------


def test_a_record_round_trips_through_json_unchanged() -> None:
    request = a_request().decided(approved=True, reason="ok")

    assert decode(encode(request)) == request
    assert decode(encode(request)).state is State.APPROVED


def test_the_encoding_is_deterministic() -> None:
    """Sorted keys: two replicas encoding the same record write the same bytes,
    which is what makes the fingerprint comparisons in `flow` mean the same
    thing wherever the record was written."""
    request = a_request()

    assert encode(request) == encode(decode(encode(request)))
