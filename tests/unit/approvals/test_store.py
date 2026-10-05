"""The in-memory store, and the two things it must refuse.

Bounded, because an authenticated caller chooses how many requests to start and
nothing obliges them to retry. And write-only through `decide`, because the one
operation this store must not offer is "grant an approval" from anywhere the
request path can reach.
"""

from __future__ import annotations

from acp.approvals.record import ApprovalRequest, State, request_for
from acp.approvals.store import ApprovalStore, InMemoryApprovalStore

NOW = 1000.0


def a_request(index: int = 0) -> ApprovalRequest:
    request = request_for(
        tenant=None,
        subject=f"alice-{index}",
        actor=None,
        tool="crm__delete_record",
        arguments={"n": index},
        rule="approve-deletes",
        now=NOW,
    )
    assert request is not None
    return request


async def test_a_created_request_can_be_read_back() -> None:
    store = InMemoryApprovalStore()
    request = a_request()

    await store.create(request)

    assert await store.get(request.token) == request


async def test_an_unknown_token_reads_as_absent() -> None:
    assert await InMemoryApprovalStore().get("nope") is None


async def test_deciding_an_unknown_token_is_not_an_error() -> None:
    """The operator side races the expiry. A request that has fallen out of the
    store is a decision arriving too late, not a crash in whatever channel task
    55 wires up."""
    assert await InMemoryApprovalStore().decide("nope", approved=True) is None


async def test_a_decided_request_cannot_be_decided_again() -> None:
    """What makes `consume` mean anything. Without it, anything holding the
    operator's credential could re-approve a spent token and hand out the same
    permission twice."""
    store = InMemoryApprovalStore()
    request = a_request()
    await store.create(request)

    await store.decide(request.token, approved=False)
    again = await store.decide(request.token, approved=True)

    assert again is not None
    assert again.state is State.DENIED


async def test_a_consumed_request_cannot_be_re_approved() -> None:
    store = InMemoryApprovalStore()
    request = a_request()
    await store.create(request)
    await store.decide(request.token, approved=True)
    await store.consume(request.token)

    await store.decide(request.token, approved=True)

    consumed = await store.get(request.token)
    assert consumed is not None
    assert consumed.state is State.CONSUMED


async def test_the_store_is_bounded_and_evicts_the_oldest() -> None:
    """A caller can start one request per call and never retry. The bound turns
    "fill the gateway's memory" into "somebody has to ask again"."""
    store = InMemoryApprovalStore(max_pending=3)
    requests = [a_request(index) for index in range(5)]
    for request in requests:
        await store.create(request)

    assert len(store) == 3
    assert await store.get(requests[0].token) is None
    assert await store.get(requests[4].token) is not None


async def test_pending_lists_only_what_is_still_waiting() -> None:
    store = InMemoryApprovalStore()
    first, second = a_request(1), a_request(2)
    await store.create(first)
    await store.create(second)

    await store.decide(first.token, approved=True)

    assert [request.token for request in await store.pending()] == [second.token]


async def test_the_in_memory_store_satisfies_the_protocol() -> None:
    """A structural check, so a signature drifting apart from the protocol is a
    type error rather than a runtime one on the day the Redis implementation
    lands."""
    store: ApprovalStore = InMemoryApprovalStore()

    assert await store.get("nothing") is None


# ---------------------------------------------------------------------------
# Eviction cannot be aimed at somebody else
# ---------------------------------------------------------------------------


def a_request_from(subject: str, index: int, *, now: float = NOW) -> ApprovalRequest:
    request = request_for(
        tenant=None,
        subject=subject,
        actor=None,
        tool="crm__delete_record",
        arguments={"n": index},
        rule="approve-deletes",
        now=now,
    )
    assert request is not None
    return request


async def test_a_flood_from_one_principal_evicts_that_principals_own_requests_first() -> None:
    """Oldest-first eviction let any caller with one gated tool push a
    colleague's pending request out of the store by asking `max_pending` times.
    A flood now costs the flooder, not the person waiting beside them."""
    store = InMemoryApprovalStore(max_pending=3)
    bobs = a_request_from("bob", 0)
    await store.create(bobs)
    for index in range(1, 6):
        await store.create(a_request_from("mallory", index))

    assert len(store) == 3
    assert await store.get(bobs.token) is bobs, "bob's older request must survive mallory's flood"
    assert sum(1 for r in await store.pending() if r.subject == "mallory") == 2


async def test_finished_requests_are_evicted_before_anyone_still_waiting() -> None:
    """A decided or consumed record is kept only so a late retry reads
    "already decided" rather than "no such request". That courtesy is the first
    thing to go when space is short — never a live pending request."""
    store = InMemoryApprovalStore(max_pending=3)
    waiting = a_request_from("bob", 0)  # the oldest, and still pending
    done = a_request_from("alice", 1)
    await store.create(waiting)
    await store.create(done)
    await store.decide(done.token, approved=True)
    await store.consume(done.token)
    await store.create(a_request_from("carol", 2))
    await store.create(a_request_from("dave", 3))  # full: something has to go

    assert await store.get(done.token) is None, "the consumed record is the victim, not the oldest"
    assert await store.get(waiting.token) is waiting


async def test_expired_requests_are_evicted_before_live_ones() -> None:
    store = InMemoryApprovalStore(max_pending=2)
    live = a_request_from("bob", 0)  # the oldest entry, and still live
    stale = a_request_from("alice", 1, now=NOW - 10_000)  # long expired by NOW
    await store.create(live)
    await store.create(stale)
    await store.create(a_request_from("carol", 2))

    assert await store.get(stale.token) is None
    assert await store.get(live.token) is live
