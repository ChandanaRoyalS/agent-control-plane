"""The approval flow: request, decide, retry — and the seven ways it stops.

Most of this file is refusals, which is the right shape for the tests of a
control whose failure mode is letting something through. The one that matters
most is `test_an_approval_does_not_authorise_a_different_call`: it is the attack
the fingerprint exists to stop, and without it every other test here would pass
against an implementation that simply trusted the token.

Time is a parameter throughout — expiry is asserted by advancing a number, never
by sleeping — so these are deterministic and fast, the same discipline the rate
limiter follows.
"""

from __future__ import annotations

from typing import Any

from acp.approvals.flow import Outcome, resolve
from acp.approvals.record import (
    DEFAULT_TTL_SECONDS,
    ApprovalRequest,
    State,
    fingerprint,
    new_token,
    request_for,
)
from acp.approvals.store import InMemoryApprovalStore

SUBJECT = "alice@example.test"
ACTOR = "agent-support"
TOOL = "crm__delete_record"
ARGS: dict[str, Any] = {"record_id": "test-1", "hard": False}
NOW = 1000.0


def a_store() -> InMemoryApprovalStore:
    return InMemoryApprovalStore()


def a_request(
    *,
    subject: str = SUBJECT,
    actor: str | None = ACTOR,
    tool: str = TOOL,
    arguments: dict[str, Any] | None = None,
    now: float = NOW,
) -> ApprovalRequest:
    request = request_for(
        subject=subject,
        actor=actor,
        tool=tool,
        arguments=ARGS if arguments is None else arguments,
        rule="approve-deletes",
        now=now,
    )
    assert request is not None
    return request


def held(store: InMemoryApprovalStore, **kwargs: Any) -> ApprovalRequest:
    request = a_request(**kwargs)
    store.create(request)
    return request


def retry(
    store: InMemoryApprovalStore,
    token: str | None,
    *,
    subject: str = SUBJECT,
    actor: str | None = ACTOR,
    tool: str = TOOL,
    arguments: dict[str, Any] | None = None,
    now: float = NOW + 1.0,
) -> Any:
    return resolve(
        store,
        token,
        subject=subject,
        actor=actor,
        tool=tool,
        arguments=ARGS if arguments is None else arguments,
        now=now,
    )


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_an_approved_call_proceeds() -> None:
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token)

    assert resolution.outcome is Outcome.PROCEED
    assert resolution.proceed


def test_a_pending_call_waits_rather_than_being_refused() -> None:
    """The only outcome that is not a refusal. Nothing changes: the caller is
    told to come back with the same token."""
    store = a_store()
    request = held(store)

    resolution = retry(store, request.token)

    assert resolution.outcome is Outcome.WAIT
    assert store.get(request.token) is not None
    assert store.get(request.token).state is State.PENDING  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# The one this module exists for
# ---------------------------------------------------------------------------


def test_an_approval_does_not_authorise_a_different_call() -> None:
    """**The attack the fingerprint exists to stop.**

    A human reads "delete test-1" and approves it. The agent retries the same
    token asking to delete production. An implementation that trusted the token
    would execute it, and every other test in this file would still pass.
    """
    store = a_store()
    request = held(store, arguments={"record_id": "test-1", "hard": False})
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, arguments={"record_id": "production", "hard": True})

    assert resolution.outcome is Outcome.REFUSE
    assert "does not match" in resolution.reason


def test_changing_one_argument_is_enough_to_break_the_binding() -> None:
    """Not just a different record — a different *anything*. The approval is for
    the call the operator read, down to the last argument."""
    store = a_store()
    request = held(store, arguments={"record_id": "test-1", "hard": False})
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, arguments={"record_id": "test-1", "hard": True})

    assert resolution.outcome is Outcome.REFUSE


def test_the_same_call_written_differently_still_matches() -> None:
    """Canonicalised, so key order is not a re-ask. A false *mismatch* is a
    nuisance rather than a hole, but a flow that re-asks at random is one people
    route around."""
    store = a_store()
    request = held(store, arguments={"record_id": "test-1", "hard": False})
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, arguments={"hard": False, "record_id": "test-1"})

    assert resolution.outcome is Outcome.PROCEED


def test_an_approval_is_not_transferable_between_callers() -> None:
    """Alice's approval, retried by bob. The subject is inside the fingerprint
    *and* checked explicitly — belt and braces, because this is the check that
    turns an approval into a bearer credential if it is missing."""
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, subject="bob@example.test")

    assert resolution.outcome is Outcome.REFUSE


def test_a_different_acting_agent_breaks_the_binding() -> None:
    """Both identities, per ADR 0015. Two agents acting for one person are not
    interchangeable — which is the entire reason this project carries an actor."""
    store = a_store()
    request = held(store, actor="agent-support")
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, actor="agent-research")

    assert resolution.outcome is Outcome.REFUSE


# ---------------------------------------------------------------------------
# Expiry — the default-deny
# ---------------------------------------------------------------------------


def test_an_approval_expires_and_the_default_is_deny() -> None:
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, now=NOW + DEFAULT_TTL_SECONDS + 1)

    assert resolution.outcome is Outcome.REFUSE
    assert "expired" in resolution.reason


def test_expiry_is_checked_before_the_state_so_a_late_yes_does_not_count() -> None:
    """An operator who approves after the window has closed has approved
    nothing. Checked at resolution rather than by a sweeper, so the answer is
    right even when no background job ran."""
    store = a_store()
    request = held(store)
    late = NOW + DEFAULT_TTL_SECONDS + 60
    store.decide(request.token, approved=True)

    assert retry(store, request.token, now=late).outcome is Outcome.REFUSE


def test_a_request_is_still_live_one_second_before_it_lapses() -> None:
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=True)

    resolution = retry(store, request.token, now=NOW + DEFAULT_TTL_SECONDS - 1)

    assert resolution.outcome is Outcome.PROCEED


# ---------------------------------------------------------------------------
# The rest of the seven
# ---------------------------------------------------------------------------


def test_no_token_is_a_refusal() -> None:
    assert retry(a_store(), None).outcome is Outcome.REFUSE
    assert retry(a_store(), "").outcome is Outcome.REFUSE


def test_an_invented_token_is_a_refusal() -> None:
    assert retry(a_store(), new_token()).outcome is Outcome.REFUSE


def test_a_denied_request_is_a_refusal() -> None:
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=False, reason="not this quarter")

    resolution = retry(store, request.token)

    assert resolution.outcome is Outcome.REFUSE
    assert "refused" in resolution.reason


def test_an_approval_is_single_use() -> None:
    """One approval, one call. Without this, a human's yes to one delete is a
    yes to every delete until the token lapses."""
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=True)

    assert retry(store, request.token).outcome is Outcome.PROCEED
    assert retry(store, request.token).outcome is Outcome.REFUSE


def test_the_token_is_spent_by_resolve_not_by_the_caller() -> None:
    """Consumed inside `resolve`, because a caller that has to remember to spend
    it is one that eventually does not — and that failure is silent."""
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=True)

    retry(store, request.token)

    assert store.get(request.token).state is State.CONSUMED  # type: ignore[union-attr]


def test_a_refusal_never_names_which_of_the_seven_it_was_to_the_caller() -> None:
    """The reason is on the `Resolution`, for the log. What reaches the caller is
    decided by the request path, and there is nothing here it could leak by
    accident — every refusal is the same `Outcome`."""
    store = a_store()
    request = held(store)
    store.decide(request.token, approved=False)

    outcomes = {
        retry(store, None).outcome,
        retry(store, new_token()).outcome,
        retry(store, request.token).outcome,
        retry(store, request.token, subject="bob").outcome,
    }

    assert outcomes == {Outcome.REFUSE}


# ---------------------------------------------------------------------------
# Fingerprints and tokens
# ---------------------------------------------------------------------------


def test_a_call_that_cannot_be_fingerprinted_is_never_held() -> None:
    """A value JSON cannot represent. The cache's answer is "do not store and
    carry on"; here the only safe answer is to refuse, because an approval that
    cannot be bound to a call is an approval for anything."""
    assert (
        request_for(
            subject=SUBJECT,
            actor=ACTOR,
            tool=TOOL,
            arguments={"when": {1, 2, 3}},
            rule="r",
            now=NOW,
        )
        is None
    )


def test_two_tokens_are_never_the_same() -> None:
    assert len({new_token() for _ in range(200)}) == 200


def test_the_token_is_not_derived_from_the_call() -> None:
    """Two identical calls get different tokens. A token an attacker can compute
    from a request they can guess is not a token."""
    first = a_request()
    second = a_request()

    assert first.token != second.token
    assert first.fingerprint == second.fingerprint


def test_the_fingerprint_covers_the_tool() -> None:
    assert fingerprint(subject=SUBJECT, actor=ACTOR, tool="a", arguments={}) != fingerprint(
        subject=SUBJECT, actor=ACTOR, tool="b", arguments={}
    )


def test_an_absent_actor_is_not_the_same_as_any_actor() -> None:
    assert fingerprint(subject=SUBJECT, actor=None, tool=TOOL, arguments={}) != fingerprint(
        subject=SUBJECT, actor="", tool=TOOL, arguments={}
    )
