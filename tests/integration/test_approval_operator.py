"""Integration: the channel a person answers on, and who cannot reach it.

Task 55. Two properties are worth more than the rest of this file put together,
and they are the first and last tests here.

**The agent's listener has no approval routes.** Not "has them and refuses" —
does not have them. An agent cannot approve its own call because it cannot
address the thing that approves calls, and that is a fact about the topology
rather than an `if` somebody has to keep writing correctly.

**And the whole loop closes.** A call is held on `:8080`, a person answers on
`:9090`, and the retry on `:8080` executes. Every other test in this repository
proves one half of that; only this one proves the halves are connected.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from typing import Any

import anyio
import httpx
import pytest

from acp.admin import build_admin_app
from acp.approvals import (
    APPROVALS_PATH,
    MAX_DISPLAYED_ARGUMENT_BYTES,
    InMemoryApprovalStore,
    State,
    request_for,
)
from acp.policy import Effect, Policy, Rule

from ..tokens import Keypair, claims
from .helpers import authenticated_gateway, call_gateway

pytestmark = pytest.mark.integration

CREDENTIAL = "operator-credential-for-tests"
ALICE = "alice@example.test"
TOOL = "mock-a__search"

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


def held_store(*, arguments: dict[str, Any] | None = None) -> InMemoryApprovalStore:
    """A store with exactly one pending request in it."""
    store = InMemoryApprovalStore()
    request = request_for(
        tenant=None,
        subject=ALICE,
        actor=None,
        tool=TOOL,
        arguments={"query": "x"} if arguments is None else arguments,
        rule="approve-searches",
        now=time.time(),
    )
    assert request is not None
    store.create(request)
    return store


def admin(
    method: str,
    path: str,
    *,
    store: InMemoryApprovalStore | None,
    credential: str = CREDENTIAL,
    bearer: str | None = CREDENTIAL,
    body: Any = None,
) -> httpx.Response:
    """One request to the admin listener, built exactly as an operator would."""

    async def _run() -> httpx.Response:
        app = build_admin_app(None, None, store, credential)
        transport = httpx.ASGITransport(app=app)
        headers = {} if bearer is None else {"authorization": f"Bearer {bearer}"}
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(method, path, headers=headers, json=body)

    response: httpx.Response = anyio.run(_run)
    return response


def approval_path(token: str) -> str:
    return f"{APPROVALS_PATH}/{token}"


# ---------------------------------------------------------------------------
# The separation
# ---------------------------------------------------------------------------


def test_the_gateway_listener_has_no_approval_routes(keypair: Keypair) -> None:
    """**The structural property.**

    The agent speaks to this app. If approving lived here, the one participant
    the approval exists to check would be able to perform it — and every other
    control in this package would be decoration. A 404 rather than a 401,
    because the route must not exist at all: a 401 is a promise that the thing
    is there and merely shut.
    """

    async def _run() -> int:
        async with authenticated_gateway(
            keypair, token=keypair.sign(claims()), policy=GATED, approvals=InMemoryApprovalStore()
        ) as agent:
            response = await agent.get(APPROVALS_PATH)
            return response.status_code

    assert anyio.run(_run) != 200


def test_no_credential_means_no_channel() -> None:
    """A feature nobody configured does not exist. The store is present and the
    routes are still absent, because the missing half is the entitlement."""
    response = admin("GET", APPROVALS_PATH, store=held_store(), credential="")

    assert response.status_code == 404


def test_no_store_means_no_channel() -> None:
    """The other way to have nothing to decide about."""
    response = admin("GET", APPROVALS_PATH, store=None)

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_listing_without_a_credential_is_refused() -> None:
    response = admin("GET", APPROVALS_PATH, store=held_store(), bearer=None)

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_listing_with_the_wrong_credential_is_refused() -> None:
    response = admin("GET", APPROVALS_PATH, store=held_store(), bearer="not-it")

    assert response.status_code == 401


def test_deciding_without_a_credential_is_refused() -> None:
    """The read is authenticated because of what it discloses; the write is
    authenticated because of what it grants."""
    store = held_store()
    token = store.pending()[0].token

    response = admin(
        "POST", approval_path(token), store=store, bearer=None, body={"approved": True}
    )

    assert response.status_code == 401
    assert store.pending()[0].state is State.PENDING


def test_a_refused_credential_does_not_leak_the_pending_list() -> None:
    response = admin("GET", APPROVALS_PATH, store=held_store(), bearer="not-it")

    assert TOOL not in response.text
    assert ALICE not in response.text


# ---------------------------------------------------------------------------
# What an operator sees
# ---------------------------------------------------------------------------


def test_the_pending_list_shows_the_call_being_approved() -> None:
    """An approval you cannot read is not an approval. The operator sees the
    subject, the tool, the rule that held it — and the arguments."""
    store = held_store(arguments={"query": "delete the production dataset"})

    payload = admin("GET", APPROVALS_PATH, store=store).json()

    [held] = payload["pending"]
    assert held["subject"] == ALICE
    assert held["tool"] == TOOL
    assert held["rule"] == "approve-searches"
    assert held["arguments"] == {"query": "delete the production dataset"}
    assert held["arguments_shown"] is True


def test_what_is_displayed_is_what_is_fingerprinted() -> None:
    """The property the whole design turns on, asserted rather than asserted-of.

    The bytes shown to the operator are the bytes the binding was taken over, so
    "approve the call you read" and "approve the call that runs" cannot come
    apart. A second encoder for display would be the one place they could.
    """
    arguments = {"z": 1, "a": [2, 3]}
    store = held_store(arguments=arguments)

    payload = admin("GET", APPROVALS_PATH, store=store).json()

    [held] = payload["pending"]
    assert json.dumps(held["arguments"], sort_keys=True, separators=(",", ":")) == (
        store.pending()[0].arguments_json
    )


def test_arguments_too_large_to_show_are_withheld_rather_than_truncated() -> None:
    """Truncating would display a *different* call from the one being approved —
    the exact confusion this module exists to prevent, in the one place a human
    is looking. So they are withheld, and the response says so."""
    store = held_store(arguments={"blob": "x" * (MAX_DISPLAYED_ARGUMENT_BYTES + 1)})

    payload = admin("GET", APPROVALS_PATH, store=store).json()

    [held] = payload["pending"]
    assert held["arguments"] is None
    assert held["arguments_shown"] is False
    assert held["arguments_bytes"] > MAX_DISPLAYED_ARGUMENT_BYTES


def test_every_response_carries_the_untrusted_notice() -> None:
    """The last place an injection can land is a person's screen. Whatever
    renders this is told, in the payload, that the agent chose these words."""
    payload = admin("GET", APPROVALS_PATH, store=held_store()).json()

    assert "instructions" in payload["notice"]


def test_an_expired_request_is_marked_as_such_in_the_list() -> None:
    """Or the channel's first act is to invite somebody to approve a dead call
    and believe they unblocked it."""
    store = held_store()
    stale = replace(store.pending()[0], expires_at=time.time() - 1)
    store.create(stale)

    payload = admin("GET", APPROVALS_PATH, store=store).json()

    assert payload["pending"][0]["expired"] is True


# ---------------------------------------------------------------------------
# Deciding
# ---------------------------------------------------------------------------


def test_an_approval_is_recorded() -> None:
    store = held_store()
    token = store.pending()[0].token

    response = admin("POST", approval_path(token), store=store, body={"approved": True})

    assert response.status_code == 200
    held = store.get(token)
    assert held is not None
    assert held.state is State.APPROVED


def test_a_denial_is_recorded_with_its_reason() -> None:
    store = held_store()
    token = store.pending()[0].token

    admin(
        "POST",
        approval_path(token),
        store=store,
        body={"approved": False, "reason": "not this dataset"},
    )

    held = store.get(token)
    assert held is not None
    assert held.state is State.DENIED
    assert held.reason == "not this dataset"


def test_a_request_cannot_be_decided_twice() -> None:
    """Without this, anything holding the operator credential could re-approve a
    consumed token and hand out the same permission again."""
    store = held_store()
    token = store.pending()[0].token
    admin("POST", approval_path(token), store=store, body={"approved": False})

    response = admin("POST", approval_path(token), store=store, body={"approved": True})

    assert response.status_code == 409
    held = store.get(token)
    assert held is not None
    assert held.state is State.DENIED


def test_an_expired_request_is_refused_rather_than_decided() -> None:
    """`store.decide` would record it happily and the retry would be refused on
    expiry anyway — correct, and completely opaque. The operator would see their
    approval accepted and the caller still blocked."""
    store = held_store()
    stale = replace(store.pending()[0], expires_at=time.time() - 1)
    store.create(stale)

    response = admin("POST", approval_path(stale.token), store=store, body={"approved": True})

    assert response.status_code == 409
    assert response.json()["error"] == "expired"
    held = store.get(stale.token)
    assert held is not None
    assert held.state is State.PENDING


def test_deciding_an_unknown_token_is_a_404() -> None:
    response = admin("POST", approval_path("invented"), store=held_store(), body={"approved": True})

    assert response.status_code == 404


def test_a_body_that_does_not_say_which_way_is_refused() -> None:
    """No default, for the reason `Rule.effect` has none: the two readings are
    "let it run" and "stop it", and a missing field is not a vote."""
    store = held_store()
    token = store.pending()[0].token

    response = admin("POST", approval_path(token), store=store, body={"reason": "ok I guess"})

    assert response.status_code == 400
    assert store.pending()[0].state is State.PENDING


def test_a_non_boolean_answer_is_refused() -> None:
    """`"approved": "no"` is truthy in every language that would parse it."""
    store = held_store()
    token = store.pending()[0].token

    response = admin("POST", approval_path(token), store=store, body={"approved": "no"})

    assert response.status_code == 400
    assert store.pending()[0].state is State.PENDING


def test_a_non_string_reason_is_refused() -> None:
    store = held_store()
    token = store.pending()[0].token

    response = admin(
        "POST", approval_path(token), store=store, body={"approved": True, "reason": 7}
    )

    assert response.status_code == 400


def test_a_body_that_is_not_json_is_refused() -> None:
    store = held_store()
    token = store.pending()[0].token

    async def _run() -> httpx.Response:
        app = build_admin_app(None, None, store, CREDENTIAL)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.post(
                approval_path(token),
                headers={"authorization": f"Bearer {CREDENTIAL}"},
                content=b"not json at all",
            )

    response: httpx.Response = anyio.run(_run)

    assert response.status_code == 400


def test_a_decided_request_leaves_the_pending_list() -> None:
    store = held_store()
    token = store.pending()[0].token
    admin("POST", approval_path(token), store=store, body={"approved": True})

    payload = admin("GET", APPROVALS_PATH, store=store).json()

    assert payload["pending"] == []


# ---------------------------------------------------------------------------
# The loop, closed
# ---------------------------------------------------------------------------


def test_a_person_on_the_admin_port_unblocks_a_call_on_the_gateway_port(
    keypair: Keypair,
) -> None:
    """**The test this task exists for.**

    Held on the listener the agent speaks to, answered on the listener it
    cannot, executed on the retry. Both apps share one store — an operator
    channel pointed at a second store would answer approvals nobody is waiting
    on, which is a wiring mistake that looks like a working deployment.
    """
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    params = {"name": TOOL, "arguments": {"query": "x"}}

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(
            keypair, token=signed, policy=GATED, approvals=store
        ) as agent:
            first = await call_gateway(agent, "tools/call", params)
            token = first["result"]["requestState"]

            # The other listener, the other credential, the other participant.
            operator = build_admin_app(None, None, store, CREDENTIAL)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=operator), base_url="http://admin"
            ) as console:
                answered = await console.post(
                    approval_path(token),
                    headers={"authorization": f"Bearer {CREDENTIAL}"},
                    json={"approved": True, "reason": "checked with the data team"},
                )
            assert answered.status_code == 200, answered.text

            return await call_gateway(agent, "tools/call", {**params, "requestState": token})

    payload = anyio.run(_run)

    assert payload["result"].get("resultType") != "input_required", payload
    assert payload["result"].get("content"), payload


def test_a_denial_on_the_admin_port_stops_the_call(keypair: Keypair) -> None:
    """The same loop, the other answer. A denial must reach the caller as an
    undifferentiated policy refusal — the operator's reason is for the log."""
    store = InMemoryApprovalStore()
    signed = keypair.sign(claims())
    params = {"name": TOOL, "arguments": {"query": "x"}}

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(
            keypair, token=signed, policy=GATED, approvals=store
        ) as agent:
            first = await call_gateway(agent, "tools/call", params)
            token = first["result"]["requestState"]

            operator = build_admin_app(None, None, store, CREDENTIAL)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=operator), base_url="http://admin"
            ) as console:
                await console.post(
                    approval_path(token),
                    headers={"authorization": f"Bearer {CREDENTIAL}"},
                    json={"approved": False, "reason": "production dataset"},
                )

            return await call_gateway(agent, "tools/call", {**params, "requestState": token})

    payload = anyio.run(_run)

    assert payload["error"]["code"] == -32040
    assert "production dataset" not in str(payload)
