"""Integration: the channel a person answers on, and who cannot reach it.

Two properties are worth more than the rest of this file put together,
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
from acp.approvals.operator import SHARED_OPERATOR_NAME
from acp.audit import AuditLog
from acp.audit.sink import MemoryAuditSink
from acp.identity import IssuerRegistration, IssuerRegistry, JwksCache, TokenPolicy, TokenValidator
from acp.policy import Effect, Policy, Rule

from ..tokens import AUDIENCE, ISSUER, Keypair, claims
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


# ---------------------------------------------------------------------------
# Both identities, in the view and in the record
# ---------------------------------------------------------------------------


def held_store_for_agent(actor: str, tenant: str | None) -> tuple[InMemoryApprovalStore, str]:
    store = InMemoryApprovalStore()
    request = request_for(
        tenant=tenant,
        subject=ALICE,
        actor=actor,
        tool=TOOL,
        arguments={"query": "x"},
        rule="approve-searches",
        now=time.time(),
    )
    assert request is not None
    store.create(request)
    return store, request.token


def test_the_operator_is_shown_which_agent_is_asking() -> None:
    """The actor was always in the fingerprint — an approval could never be
    spent by a different agent — but the person deciding was never told which
    of alice's agents was asking. Both identities, always (ADR 0015)."""
    store, _ = held_store_for_agent("agent-ticket-bot", "acme")

    body = admin("GET", APPROVALS_PATH, store=store).json()

    (shown,) = body["pending"]
    assert shown["subject"] == ALICE
    assert shown["actor"] == "agent-ticket-bot"
    assert shown["tenant"] == "acme"


def test_the_decision_row_names_the_agent_and_tenant_and_never_the_token() -> None:
    """The audit row is the one record of a human's decision. It must say who
    asked — subject, acting agent, tenant — and must not carry `request_state`,
    which is a live handle for five minutes in a file that is durable and
    widely readable (ADR 0045)."""
    sink = MemoryAuditSink()
    audit = AuditLog(sink, required=True)
    store, token = held_store_for_agent("agent-ticket-bot", "acme")

    async def _run() -> httpx.Response:
        app = build_admin_app(None, None, store, CREDENTIAL, audit)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.post(
                approval_path(token),
                headers={"authorization": f"Bearer {CREDENTIAL}"},
                json={"approved": True, "reason": "checked with the data team"},
            )

    response: httpx.Response = anyio.run(_run)
    assert response.status_code == 200

    (row,) = [json.loads(line)["record"] for line in sink.lines()]
    assert row["event"] == "approval.decided"
    assert row["subject"] == ALICE
    assert row["actor"] == "agent-ticket-bot"
    assert row["tenant"] == "acme"
    assert row["detail"]["fingerprint"] == store.get(token).fingerprint  # type: ignore[union-attr]
    assert "request_state" not in row["detail"]
    assert token not in json.dumps(row), "the live request_state must not reach the chain"
    # Answered with the shared token, and the row says exactly that rather than
    # leaving the operator blank or letting configuration assert a name.
    assert row["detail"]["operator"] == SHARED_OPERATOR_NAME
    assert row["detail"]["operator_verified"] is False


def test_a_non_ascii_bearer_is_a_401_not_a_500() -> None:
    """`compare_digest` over `str` raises `TypeError` for non-ASCII input, which
    made an unauthenticated request carrying one a 500 on the admin listener."""
    store = held_store(arguments={"query": "x"})

    async def _run() -> httpx.Response:
        app = build_admin_app(None, None, store, CREDENTIAL)
        transport = httpx.ASGITransport(app=app)
        # Header values are bytes on the wire; latin-1 is what the ASGI server
        # decodes them with, so this arrives as the `str` "Bearer pässwörd".
        headers = {b"authorization": "Bearer pässwörd".encode("latin-1")}
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.get(APPROVALS_PATH, headers=headers)

    response: httpx.Response = anyio.run(_run)

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Operators who prove who they are
# ---------------------------------------------------------------------------

OPERATOR_AUDIENCE = "acp-operators"


def operator_validator(keypair: Keypair, *, tenant: str | None = None) -> TokenValidator:
    """The request path's validator, re-targeted at the operator audience —
    exactly what `build_operator_validator` does from settings."""

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    registration = IssuerRegistration(
        policy=TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys=keys, tenant=tenant
    )
    gateway_side = TokenValidator(issuers=IssuerRegistry([registration]))
    return TokenValidator(issuers=gateway_side.issuers.for_audience(OPERATOR_AUDIENCE))


def operator_token(keypair: Keypair, subject: str = "oncall@example.test") -> str:
    return keypair.sign(claims(sub=subject, aud=OPERATOR_AUDIENCE, act=None))


def admin_with_jwt(
    method: str,
    path: str,
    *,
    store: InMemoryApprovalStore,
    validator: TokenValidator,
    bearer: str,
    audit: AuditLog | None = None,
    body: Any = None,
) -> httpx.Response:
    async def _run() -> httpx.Response:
        # No shared token at all: the JWT is the only way in.
        app = build_admin_app(None, None, store, "", audit, operator_validator=validator)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(
                method, path, headers={"authorization": f"Bearer {bearer}"}, json=body
            )

    response: httpx.Response = anyio.run(_run)
    return response


def test_a_verified_operator_decides_and_the_row_names_them(keypair: Keypair) -> None:
    """The point of the whole change: the audit row records a subject an
    authorization server vouched for, not a label a config file asserted."""
    sink = MemoryAuditSink()
    audit = AuditLog(sink, required=True)
    store, token = held_store_for_agent("agent-ticket-bot", "acme")

    response = admin_with_jwt(
        "POST",
        approval_path(token),
        store=store,
        validator=operator_validator(keypair, tenant="acme"),
        bearer=operator_token(keypair),
        audit=audit,
        body={"approved": True, "reason": "checked the ticket"},
    )

    assert response.status_code == 200, response.text
    (row,) = [json.loads(line)["record"] for line in sink.lines()]
    assert row["detail"]["operator"] == "oncall@example.test"
    assert row["detail"]["operator_issuer"] == ISSUER
    assert row["detail"]["operator_verified"] is True


def test_an_agents_token_cannot_open_the_operator_channel(keypair: Keypair) -> None:
    """Same issuer, same keys, correctly signed — minted for the *gateway*.
    The audience is what keeps "may call tools" and "may approve them" apart,
    and a token that is one must not be the other."""
    store, token = held_store_for_agent("agent-7", None)
    agents_token = keypair.sign(claims())  # aud = the gateway's audience

    response = admin_with_jwt(
        "POST",
        approval_path(token),
        store=store,
        validator=operator_validator(keypair),
        bearer=agents_token,
        body={"approved": True},
    )

    assert response.status_code == 401
    assert store.get(token).state is State.PENDING  # type: ignore[union-attr]


def test_an_operator_from_another_tenant_is_refused(keypair: Keypair) -> None:
    """acme's operator, however valid their token, does not approve globex's
    delete. The tenant comes from the issuer registration (ADR 0051), so it is
    not something the token can claim its way across."""
    store, token = held_store_for_agent("agent-7", "globex")

    response = admin_with_jwt(
        "POST",
        approval_path(token),
        store=store,
        validator=operator_validator(keypair, tenant="acme"),
        bearer=operator_token(keypair),
        body={"approved": True},
    )

    assert response.status_code == 403
    assert store.get(token).state is State.PENDING  # type: ignore[union-attr]


def test_the_listing_shows_an_operator_only_their_tenants_queue(keypair: Keypair) -> None:
    store = InMemoryApprovalStore()
    for tenant in ("acme", "globex", "acme"):
        request = request_for(
            tenant=tenant,
            subject=ALICE,
            actor="agent-7",
            tool=TOOL,
            arguments={"query": tenant},
            rule="approve-searches",
            now=time.time(),
        )
        assert request is not None
        store.create(request)

    body = admin_with_jwt(
        "GET",
        APPROVALS_PATH,
        store=store,
        validator=operator_validator(keypair, tenant="acme"),
        bearer=operator_token(keypair),
    ).json()

    assert body["operator"] == "oncall@example.test"
    assert [held["tenant"] for held in body["pending"]] == ["acme", "acme"]


def test_with_neither_token_nor_validator_the_routes_are_absent() -> None:
    store = held_store()

    async def _run() -> int:
        app = build_admin_app(None, None, store, "", None, operator_validator=None)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return (await client.get(APPROVALS_PATH)).status_code

    assert anyio.run(_run) == 404


# ---------------------------------------------------------------------------
# A decision the gateway cannot record is not made
# ---------------------------------------------------------------------------


class _FullDisk:
    """An audit sink that cannot write — declared blocking, so the write would
    have gone through the threaded `arecord` path a real file sink uses."""

    head = "0" * 64
    length = 0
    blocking = True

    def append(self, _record: Any) -> Any:
        raise OSError("no space left on device")


def test_a_decision_the_audit_log_refuses_is_not_made() -> None:
    """Fail-closed, on the one human write in the system. The row is chained
    *before* the store changes state, so a log that refuses leaves the request
    pending — answerable again later — rather than approved and unrecorded.
    Previously the store was updated first and the write was a synchronous
    `record` on the event loop, which both bypassed the writer's serialisation
    and, on failure, left an approval nobody could account for."""
    audit = AuditLog(_FullDisk(), required=True)  # type: ignore[arg-type]
    store, token = held_store_for_agent("agent-7", "acme")

    async def _run() -> httpx.Response:
        app = build_admin_app(None, None, store, CREDENTIAL, audit)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.post(
                approval_path(token),
                headers={"authorization": f"Bearer {CREDENTIAL}"},
                json={"approved": True},
            )

    response: httpx.Response = anyio.run(_run)

    assert response.status_code == 503
    assert store.get(token).state is State.PENDING  # type: ignore[union-attr]
