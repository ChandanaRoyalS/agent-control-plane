"""Integration test: tools/list shows only what the principal may call.

The visibility half of policy, on the real path — a real token through the real
middleware sets the principal that on_list_tools filters by. Built on the same
lifespan-aware harness as test_gateway_server: the SDK's streamable-HTTP app
starts its session-manager task group in the ASGI lifespan.

Paired with test_policy_enforcement (task 34b): that proves a denied call is
refused; this proves a denied tool is never offered.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.gateway import UpstreamRegistry, build_app
from acp.identity import AuthenticationMiddleware
from acp.identity.issuers import single_issuer
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator
from acp.mocks import mock_a, mock_b
from acp.policy import Effect, Policy, Rule
from acp.upstream import UpstreamClient, UpstreamConfig

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}


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


def list_tools(policy: Policy, keypair: Keypair, token: str) -> list[str]:
    """POST tools/list through the full gateway with policy filtering, and
    return the visible qualified tool names."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    async def _run() -> list[str]:
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
            policy=policy,
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
                    headers={**MCP_HEADERS, "authorization": f"Bearer {token}"},
                )
                parsed = _parse(response)
                tools: list[dict[str, Any]] = parsed["result"]["tools"]
                return [str(t["name"]) for t in tools]
        raise AssertionError("unreachable")

    result: list[str] = anyio.run(_run)
    return result


def test_only_allowed_tools_are_listed(keypair: Keypair) -> None:
    """The catalogue shows exactly the tools the policy allows — a denied tool is
    absent, not merely un-callable."""
    policy = Policy(
        rules=(
            Rule(
                name="allow-alice-search",
                effect=Effect.ALLOW,
                tools=("mock-a__search", "mock-b__search"),
            ),
        )
    )
    token = keypair.sign(claims())
    names = list_tools(policy, keypair, token)
    assert names == ["mock-a__search", "mock-b__search"]


def test_deny_default_shows_an_empty_catalogue(keypair: Keypair) -> None:
    """An empty policy hides every tool — nothing is offered."""
    token = keypair.sign(claims())
    assert list_tools(Policy(), keypair, token) == []


def test_a_denied_tool_does_not_appear(keypair: Keypair) -> None:
    """A broad allow with a narrow deny lists everything but the denied tool."""
    policy = Policy(
        rules=(
            Rule(name="deny-create", effect=Effect.DENY, tools=("mock-a__create_ticket",)),
            Rule(name="allow-all", effect=Effect.ALLOW),
        )
    )
    token = keypair.sign(claims())
    names = list_tools(policy, keypair, token)
    assert "mock-a__create_ticket" not in names
    assert "mock-a__search" in names
