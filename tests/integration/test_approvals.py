"""Integration: a held call, an operator's answer, and the retry that lands.

The unit tests prove the decision table. Only this proves the *shape* — that a
real request through the real middleware comes back as `input_required` carrying
a token a client can read, and that sending that token back on a real retry
executes the call.

Driven through `helpers.authenticated_gateway`, which starts the ASGI lifespan
(the SDK's streamable-HTTP app starts its session-manager task group there) and
whose transport completes every request's envelope and routing headers.

**That last part is not a tidiness note.** This file was originally written with
a hand-rolled request that omitted the 2026-07-28 envelope. The SDK picks a
result surface by `(method, version)` and `InputRequiredResult` exists only at
2026-07-28 — every earlier version maps `tools/call` to a bare `CallToolResult`
— so the gateway's correct `input_required` answer could not serialise and came
back as `-32603 Handler returned an invalid result`. The helper that would have
prevented it already existed. See `helpers` for what was done about that.

**The assertion that matters most is the last one.** An agent that answers its
own `input_responses` must gain nothing, because the caller of this gateway is
the agent and Phase 5's whole premise is that agents read hostile text.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any

import anyio
import pytest

from acp.approvals import InMemoryApprovalStore, State
from acp.policy import Effect, Policy, Rule

from ..tokens import Keypair, claims
from .helpers import authenticated_gateway, call_gateway

pytestmark = pytest.mark.integration

ALICE = "alice@example.test"
TOOL = "mock-a__search"
ARGUMENTS = {"query": "x"}

GATED = Policy(
    rules=(
        Rule(
            name="approve-searches",
            effect=Effect.REQUIRE_APPROVAL,
            subjects=(ALICE,),
            tools=(TOOL,),
        ),
    )
)


def call(
    store: InMemoryApprovalStore | None,
    keypair: Keypair,
    token: str,
    *,
    request_state: str | None = None,
    arguments: dict[str, Any] | None = None,
    input_responses: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST one tools/call through the full gateway with approvals wired."""
    params: dict[str, Any] = {
        "name": TOOL,
        "arguments": ARGUMENTS if arguments is None else arguments,
    }
    if request_state is not None:
        params["requestState"] = request_state
    if input_responses is not None:
        params["inputResponses"] = input_responses

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(
            keypair, token=token, policy=GATED, approvals=store
        ) as agent:
            return await call_gateway(agent, "tools/call", params)

    return anyio.run(_run)


def request_state_of(payload: dict[str, Any]) -> str:
    """The token out of an `input_required` answer, or a readable failure.

    Read off the JSON-RPC result rather than a model, because what matters is
    that it reached *the wire* — a field the SDK dropped would be invisible to
    any assertion made against a constructed object.
    """
    result = payload.get("result", {})
    assert result.get("resultType") == "input_required", payload
    state = result.get("requestState")
    assert isinstance(state, str), f"no requestState on the wire: {payload}"
    assert state, f"empty requestState on the wire: {payload}"
    return state


# ---------------------------------------------------------------------------


def test_a_gated_call_comes_back_as_input_required(keypair: Keypair) -> None:
    store = InMemoryApprovalStore()

    payload = call(store, keypair, keypair.sign(claims()))

    assert request_state_of(payload)
    assert len(store.pending()) == 1


def test_the_upstream_is_not_called_while_the_call_is_held(keypair: Keypair) -> None:
    """A held call has not happened. The `input_required` answer carries no tool
    content, which is the observable form of that."""
    payload = call(InMemoryApprovalStore(), keypair, keypair.sign(claims()))

    assert not payload["result"].get("content")


def test_polling_returns_the_same_token(keypair: Keypair) -> None:
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    first = request_state_of(call(store, keypair, signed))

    second = request_state_of(call(store, keypair, signed, request_state=first))

    assert second == first


def test_an_approved_retry_reaches_the_upstream(keypair: Keypair) -> None:
    """The whole flow, end to end: held, approved out of band, retried, executed."""
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    state = request_state_of(call(store, keypair, signed))

    store.decide(state, approved=True)
    payload = call(store, keypair, signed, request_state=state)

    result = payload["result"]
    assert result.get("resultType") != "input_required", payload
    assert result.get("content"), payload


def test_a_denied_retry_is_refused_with_the_policy_code(keypair: Keypair) -> None:
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    state = request_state_of(call(store, keypair, signed))

    store.decide(state, approved=False)
    payload = call(store, keypair, signed, request_state=state)

    assert payload["error"]["code"] == -32040


def test_an_approval_does_not_authorise_a_different_call(keypair: Keypair) -> None:
    """The attack the fingerprint exists to stop, on the real request path."""
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    state = request_state_of(call(store, keypair, signed, arguments={"query": "safe"}))
    store.decide(state, approved=True)

    payload = call(
        store, keypair, signed, request_state=state, arguments={"query": "something else"}
    )

    assert payload["error"]["code"] == -32040


def test_an_agent_cannot_approve_its_own_call(keypair: Keypair) -> None:
    """**The assertion this file exists for.**

    MRTR lets a client answer the questions a server asked, and the client here
    is the agent. An agent talked into a destructive call by a poisoned document
    is exactly the one that will answer "yes" on its own behalf, so
    `input_responses` is read by nobody: the retry below sends a fabricated
    approval and must still be told to wait.
    """
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    state = request_state_of(call(store, keypair, signed))

    payload = call(
        store,
        keypair,
        signed,
        request_state=state,
        input_responses={"approval": {"action": "accept", "content": {"approved": True}}},
    )

    assert request_state_of(payload) == state
    still_held = store.get(state)
    assert still_held is not None
    assert still_held.state is State.PENDING


def test_an_expired_approval_is_refused(keypair: Keypair) -> None:
    """Default-deny on expiry, on the real path. The record is aged by rewriting
    its expiry rather than by sleeping for five minutes."""
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    state = request_state_of(call(store, keypair, signed))
    store.decide(state, approved=True)

    lapsed = store.get(state)
    assert lapsed is not None
    # Aged by rewriting the record rather than by sleeping, and through the
    # store's own `create` rather than by reaching into it — the token is the
    # key, so this replaces the entry in place with no private access.
    store.create(replace(lapsed, expires_at=time.time() - 1))

    payload = call(store, keypair, signed, request_state=state)

    assert payload["error"]["code"] == -32040


def test_a_policy_that_holds_a_call_with_no_store_fails_closed(keypair: Keypair) -> None:
    """`require_approval` with nothing to record it in is a misconfiguration, and
    the worst possible reading of that word is `allow`. Refused, like a loaded
    policy with no principal."""
    payload = call(None, keypair, keypair.sign(claims()))

    assert payload["error"]["code"] == -32040


def test_the_held_call_carries_the_arguments_an_operator_must_read(keypair: Keypair) -> None:
    """A person cannot approve what they cannot see (task 55).

    Asserted here rather than only in the unit tests because the value has to
    survive the whole request path — the arguments an operator is shown are the
    ones the *request* sent, not a default the handler passed along.
    """
    store = InMemoryApprovalStore()

    call(store, keypair, keypair.sign(claims()), arguments={"query": "the real one"})

    held = store.pending()[0]
    assert held.arguments_json == '{"query":"the real one"}'
