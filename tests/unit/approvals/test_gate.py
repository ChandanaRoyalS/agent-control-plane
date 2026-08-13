"""`gate`: the request path's whole approval decision, without any of MCP.

`resolve` answers "what does this token mean". `gate` answers the question the
handler actually has: *a call just arrived and the policy held it — now what?*
The difference is the first ask, where there is no token yet.

Two branches, and which one runs is decided by whether the caller sent a token —
not by whether a pending request exists for this call. That distinction is
asserted below, because looking a request up by fingerprint instead is the
obvious shortcut and it lets one caller's poll attach to another's approval.
"""

from __future__ import annotations

from typing import Any

from acp.approvals.flow import Outcome, gate
from acp.approvals.record import DEFAULT_TTL_SECONDS, State
from acp.approvals.store import InMemoryApprovalStore

SUBJECT = "alice@example.test"
ACTOR = "agent-support"
TOOL = "crm__delete_record"
ARGS: dict[str, Any] = {"record_id": "test-1"}
NOW = 1000.0


def ask(
    store: InMemoryApprovalStore,
    *,
    token: str | None = None,
    subject: str = SUBJECT,
    arguments: dict[str, Any] | None = None,
    now: float = NOW,
) -> Any:
    return gate(
        store,
        token=token,
        tenant=None,
        subject=subject,
        actor=ACTOR,
        tool=TOOL,
        arguments=ARGS if arguments is None else arguments,
        rule="approve-deletes",
        now=now,
    )


def test_a_first_ask_creates_a_pending_request_and_returns_a_token() -> None:
    store = InMemoryApprovalStore()

    result = ask(store)

    assert result.outcome is Outcome.WAIT
    assert result.token
    assert result.expires_at == NOW + DEFAULT_TTL_SECONDS
    assert len(store.pending()) == 1


def test_the_call_does_not_proceed_on_the_first_ask() -> None:
    """Obvious, and worth an assertion: the whole feature is that this one call
    does not happen yet."""
    assert ask(InMemoryApprovalStore()).outcome is not Outcome.PROCEED


def test_a_poll_returns_the_same_token_rather_than_minting_one() -> None:
    """A new token per poll would leave the old request pending and approvable —
    an operator's yes landing on a token nobody is holding any more."""
    store = InMemoryApprovalStore()
    first = ask(store)

    second = ask(store, token=first.token)

    assert second.outcome is Outcome.WAIT
    assert second.token == first.token
    assert len(store.pending()) == 1


def test_an_approved_poll_proceeds() -> None:
    store = InMemoryApprovalStore()
    first = ask(store)
    store.decide(first.token, approved=True)

    assert ask(store, token=first.token).outcome is Outcome.PROCEED


def test_the_branch_is_chosen_by_the_token_not_by_a_matching_request() -> None:
    """**The shortcut this avoids.** A pending request exists for exactly this
    call, and the caller did not send its token — so this is a fresh ask, not a
    poll. Matching by fingerprint instead would let any caller who can guess a
    call attach to somebody else's pending approval."""
    store = InMemoryApprovalStore()
    first = ask(store)
    store.decide(first.token, approved=True)

    second = ask(store)

    assert second.outcome is Outcome.WAIT
    assert second.token != first.token


def test_losing_a_token_costs_a_re_ask_and_nothing_else() -> None:
    store = InMemoryApprovalStore()

    tokens = {ask(store).token for _ in range(3)}

    assert len(tokens) == 3
    assert len(store.pending()) == 3


def test_a_forged_token_is_refused_rather_than_starting_a_new_request() -> None:
    """A caller who sends a token gets it resolved, and an unknown one is a
    refusal. Falling back to "start a fresh approval" would turn every bad token
    into a free retry and make the seven refusals unreachable."""
    result = ask(InMemoryApprovalStore(), token="not-a-real-token")

    assert result.outcome is Outcome.REFUSE
    assert result.token is None


def test_a_denied_request_refuses_and_offers_no_token_back() -> None:
    store = InMemoryApprovalStore()
    first = ask(store)
    store.decide(first.token, approved=False)

    result = ask(store, token=first.token)

    assert result.outcome is Outcome.REFUSE
    assert result.token is None


def test_an_approved_token_used_against_a_different_call_is_refused() -> None:
    """The fingerprint check, reached through the gate rather than directly —
    because this is the path the gateway actually takes."""
    store = InMemoryApprovalStore()
    first = ask(store, arguments={"record_id": "test-1"})
    store.decide(first.token, approved=True)

    result = ask(store, token=first.token, arguments={"record_id": "production"})

    assert result.outcome is Outcome.REFUSE


def test_an_unfingerprintable_call_is_refused_rather_than_held() -> None:
    """Nothing is created. An approval that cannot be bound to a call is an
    approval for anything, so there is nothing safe to hold."""
    store = InMemoryApprovalStore()

    result = ask(store, arguments={"when": {1, 2}})

    assert result.outcome is Outcome.REFUSE
    assert len(store.pending()) == 0


def test_a_lapsed_approval_refuses_on_the_poll() -> None:
    store = InMemoryApprovalStore()
    first = ask(store)
    store.decide(first.token, approved=True)

    result = ask(store, token=first.token, now=NOW + DEFAULT_TTL_SECONDS + 1)

    assert result.outcome is Outcome.REFUSE


def test_the_expiry_hint_shrinks_as_the_window_closes() -> None:
    """What the caller is told is a hint. The check that matters happens at
    resolution, so a hint going stale costs nothing."""
    store = InMemoryApprovalStore()
    first = ask(store)

    later = ask(store, token=first.token, now=NOW + 100)

    assert later.expires_at == first.expires_at


def test_an_approval_spent_through_the_gate_cannot_be_spent_again() -> None:
    store = InMemoryApprovalStore()
    first = ask(store)
    store.decide(first.token, approved=True)

    assert ask(store, token=first.token).outcome is Outcome.PROCEED
    assert ask(store, token=first.token).outcome is Outcome.REFUSE
    held = store.get(first.token)
    assert held is not None
    assert held.state is State.CONSUMED
