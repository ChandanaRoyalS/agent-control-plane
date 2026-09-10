"""Approvals that survive a restart, and the eviction that stopped crossing tenants.

The in-memory store's limit is a *correctness* cut, not an accuracy one: a
gateway that answered `input_required`, took a person's yes and then restarted
tells the caller no for a call that was approved.
"""

from __future__ import annotations

import time
from pathlib import Path

from acp.approvals.record import ApprovalRequest, State, request_for
from acp.approvals.sqlite_store import SqliteApprovalStore
from acp.approvals.store import InMemoryApprovalStore

TOOL = "mock-b__delete_record"


def held(
    subject: str = "alice", tenant: str | None = None, created: float | None = None
) -> ApprovalRequest:
    request = request_for(
        tenant=tenant,
        subject=subject,
        actor=None,
        tool=TOOL,
        arguments={"dataset": "production"},
        rule="hold-production",
        now=time.time() if created is None else created,
    )
    assert request is not None
    return request


class TestDurability:
    def test_a_pending_approval_survives_a_restart(self, tmp_path: Path) -> None:
        """**The correctness cut ADR 0048 names first.**"""
        request = held()
        store = SqliteApprovalStore(tmp_path / "approvals.db")
        store.create(request)
        store.close()

        restarted = SqliteApprovalStore(tmp_path / "approvals.db")
        recovered = restarted.get(request.token)

        assert recovered is not None
        assert recovered.state is State.PENDING
        # Byte-identical to what was fingerprinted, or the retry cannot match.
        assert recovered.fingerprint == request.fingerprint
        assert recovered.arguments_json == request.arguments_json

    def test_a_decision_survives_a_restart(self, tmp_path: Path) -> None:
        request = held()
        store = SqliteApprovalStore(tmp_path / "approvals.db")
        store.create(request)
        store.decide(request.token, approved=True, reason="checked")
        store.close()

        restarted = SqliteApprovalStore(tmp_path / "approvals.db")
        recovered = restarted.get(request.token)

        assert recovered is not None
        assert recovered.state is State.APPROVED
        assert recovered.reason == "checked"

    def test_a_spent_approval_cannot_be_respent_after_a_restart(self, tmp_path: Path) -> None:
        """The single-use property is what `consume` is for, and losing it
        across a restart would be worse than losing the approval."""
        request = held()
        store = SqliteApprovalStore(tmp_path / "approvals.db")
        store.create(request)
        store.decide(request.token, approved=True)
        store.consume(request.token)
        store.close()

        restarted = SqliteApprovalStore(tmp_path / "approvals.db")

        again = restarted.decide(request.token, approved=True)
        assert again is not None
        assert again.state is State.CONSUMED


class TestEvictionStaysInsideOneTenant:
    """The store used to drop the globally-oldest record regardless of tenant,
    so 256 calls from any gated principal pushed every other tenant's pending
    approvals out — a cross-tenant denial of service costing one authenticated
    caller nothing.
    """

    def test_sqlite_eviction_does_not_cross_tenants(self, tmp_path: Path) -> None:
        store = SqliteApprovalStore(tmp_path / "approvals.db", max_pending=4)
        theirs = held(subject="victim", tenant="acme")
        store.create(theirs)

        for index in range(20):
            store.create(held(subject=f"noisy{index}", tenant="globex"))

        assert store.get(theirs.token) is not None

    def test_in_memory_eviction_does_not_cross_tenants(self) -> None:
        store = InMemoryApprovalStore(max_pending=4)
        theirs = held(subject="victim", tenant="acme")
        store.create(theirs)

        for index in range(20):
            store.create(held(subject=f"noisy{index}", tenant="globex"))

        assert store.get(theirs.token) is not None

    def test_a_tenant_can_still_fill_its_own_store(self) -> None:
        """The bound is still a bound. One tenant filling it costs its own
        users a re-ask, which is the cost it was always meant to impose."""
        store = InMemoryApprovalStore(max_pending=4)
        first = held(subject="early", tenant="acme")
        store.create(first)

        for index in range(10):
            store.create(held(subject=f"later{index}", tenant="acme"))

        assert store.get(first.token) is None

    def test_spent_records_are_swept_before_pending_ones_are_evicted(self) -> None:
        """Decided and consumed records are history, not pressure. They used to
        compete for the same room as live requests."""
        store = InMemoryApprovalStore(max_pending=3)
        spent = held(subject="done", tenant="acme")
        store.create(spent)
        store.decide(spent.token, approved=True)
        store.consume(spent.token)

        live = held(subject="waiting", tenant="acme")
        store.create(live)
        store.create(held(subject="other", tenant="acme"))

        assert store.get(live.token) is not None
        assert store.get(spent.token) is None
