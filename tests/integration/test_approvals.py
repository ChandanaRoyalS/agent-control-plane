"""Integration: a held call, an operator's answer, and the retry that lands.

The unit tests prove the decision table. Only this proves the *shape* — that a
real request through the real middleware comes back as `input_required` carrying
a token a client can read, and that sending that token back on a real retry
executes the call.

Driven exactly like `test_policy_enforcement.call_tool`: the SDK's streamable
HTTP app starts its session-manager task group in the ASGI lifespan, so the
request must run inside `app.router.lifespan_context`.

**The assertion that matters most is the last one.** An agent that answers its
own `input_responses` must gain nothing, because the caller of this gateway is
the agent and Phase 5's whole premise is that agents read hostile text.
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import replace
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.approvals import InMemoryApprovalStore, State
from acp.gateway import UpstreamRegistry, build_app
from acp.identity import AuthenticationMiddleware
from acp.identity.issuers import single_issuer
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator
from acp.mocks import mock_a, mock_b
from acp.policy import Effect, Policy, Rule
from acp.upstream import UpstreamClient, UpstreamConfig
from acp.upstream.envelope import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    PROTOCOL_VERSION_META_KEY,
)
from acp.upstream.models import PROTOCOL_VERSION

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
    # The version is negotiated on the WIRE, not in the body. Without this the
    # transport serves 2025-03-26 - the revision that introduced streamable
    # HTTP - and at that version `tools/call` maps to a bare `CallToolResult`,
    # so an `input_required` answer cannot be serialised at all.
    #
    # `test_spec_conformance` has sent this header since task 8; the approval
    # tests were written from `test_policy_enforcement`, which does not, because
    # a plain result validates at every version and nothing before now could
    # notice the difference.
    MCP_PROTOCOL_VERSION_HEADER: PROTOCOL_VERSION,
    # Mandatory at 2026-07-28, and only checked once the version above is sent -
    # which is why raising the version turned on a validation the earlier runs
    # never reached. Every request in this file is a tools/call.
    MCP_METHOD_HEADER: "tools/call",
}

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


def _validator(keypair: Keypair) -> TokenValidator:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    return TokenValidator(
        issuers=single_issuer(TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys)
    )


def _parse(response: httpx.Response) -> dict[str, Any]:
    text = response.text
    if text.lstrip().startswith("{"):
        parsed: dict[str, Any] = response.json()
        return parsed
    for line in text.splitlines():
        if line.startswith("data:"):
            frame: dict[str, Any] = json.loads(line[len("data:") :].strip())
            return frame
    msg = f"could not parse gateway response: {text[:200]!r}"
    raise AssertionError(msg)


def call(
    store: InMemoryApprovalStore,
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
        # Load-bearing, not decorative. The SDK picks a result surface by
        # `(method, version)`, and `InputRequiredResult` exists only at
        # 2026-07-28 - earlier versions map `tools/call` to a bare
        # `CallToolResult`. A request with no envelope is served as an older
        # client and the `input_required` answer fails to serialise. That is
        # correct and fail-closed; it is not legible, which task 55 fixes.
        "_meta": {
            PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION,
            CLIENT_CAPABILITIES_META_KEY: {},
            CLIENT_INFO_META_KEY: {"name": "approval-test", "version": "1"},
        },
    }
    if request_state is not None:
        params["requestState"] = request_state
    if input_responses is not None:
        params["inputResponses"] = input_responses
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}

    async def _run() -> dict[str, Any]:
        clients = [
            UpstreamClient(
                UpstreamConfig(name="mock-a", url="http://mock/mcp"),
                httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_a.app)),
            ),
            UpstreamClient(
                UpstreamConfig(name="mock-b", url="http://mock/mcp"),
                httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_b.app)),
            ),
        ]
        app: Starlette = build_app(
            UpstreamRegistry(clients),
            validator=_validator(keypair),
            policy=GATED,
            approvals=store,
        )
        app.add_middleware(AuthenticationMiddleware, validator=_validator(keypair))

        async with contextlib.AsyncExitStack() as stack:
            for client in clients:
                await stack.enter_async_context(client)
            await stack.enter_async_context(app.router.lifespan_context(app))

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as agent:
                response = await agent.post(
                    "/mcp",
                    json=body,
                    headers={
                        **MCP_HEADERS,
                        MCP_NAME_HEADER: TOOL,
                        "authorization": f"Bearer {token}",
                    },
                )
                return _parse(response)
        raise AssertionError("unreachable")

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

    async def _run() -> dict[str, Any]:
        clients = [
            UpstreamClient(
                UpstreamConfig(name="mock-a", url="http://mock/mcp"),
                httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_a.app)),
            ),
        ]
        app: Starlette = build_app(
            UpstreamRegistry(clients),
            validator=_validator(keypair),
            policy=GATED,
        )
        app.add_middleware(AuthenticationMiddleware, validator=_validator(keypair))
        async with contextlib.AsyncExitStack() as stack:
            for client in clients:
                await stack.enter_async_context(client)
            await stack.enter_async_context(app.router.lifespan_context(app))
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as agent:
                response = await agent.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": TOOL,
                            "arguments": ARGUMENTS,
                            "_meta": {
                                PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION,
                                CLIENT_CAPABILITIES_META_KEY: {},
                            },
                        },
                    },
                    headers={
                        **MCP_HEADERS,
                        MCP_NAME_HEADER: TOOL,
                        "authorization": f"Bearer {keypair.sign(claims())}",
                    },
                )
                return _parse(response)
        raise AssertionError("unreachable")

    payload = anyio.run(_run)

    assert payload["error"]["code"] == -32040
