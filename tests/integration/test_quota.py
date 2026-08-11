"""Integration test: a caller over their quota is refused on the real path.

Reuses the task-38 rate-limiting harness — real token, real middleware, a
principal keyed by subject — with a small quota so the window fills in a few
calls and the next one comes back as the quota error.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.budget import QuotaCounter
from acp.gateway import UpstreamRegistry, build_app
from acp.identity import AuthenticationMiddleware
from acp.identity.issuers import single_issuer
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator
from acp.mocks import mock_a, mock_b
from acp.upstream import UpstreamClient, UpstreamConfig

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}

QUOTA_CODE = -32051


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


def _call_codes(quota: QuotaCounter, keypair: Keypair, token: str, n: int) -> list[int | None]:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "mock-a__search", "arguments": {"query": "x"}},
    }

    async def _run() -> list[int | None]:
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
            UpstreamRegistry(clients), validator=_validator(keypair), quota=quota
        )
        app.add_middleware(AuthenticationMiddleware, validator=_validator(keypair))

        codes: list[int | None] = []
        async with contextlib.AsyncExitStack() as stack:
            for client in clients:
                await stack.enter_async_context(client)
            await stack.enter_async_context(app.router.lifespan_context(app))
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as agent:
                for _ in range(n):
                    resp = await agent.post(
                        "/mcp",
                        json=body,
                        headers={**MCP_HEADERS, "authorization": f"Bearer {token}"},
                    )
                    parsed = _parse(resp)
                    codes.append(parsed["error"]["code"] if "error" in parsed else None)
        return codes

    return anyio.run(_run)


def test_calls_within_the_quota_are_served_then_the_next_is_refused(keypair: Keypair) -> None:
    """A limit-2 quota serves two calls, then refuses the third with the quota
    code — on the real authenticated path."""
    quota = QuotaCounter(limit=2, window_seconds=86400.0)
    token = keypair.sign(claims())
    codes = _call_codes(quota, keypair, token, 3)
    assert codes[0] != QUOTA_CODE
    assert codes[1] != QUOTA_CODE
    assert codes[2] == QUOTA_CODE


def test_the_quota_is_not_shared_between_callers(keypair: Keypair) -> None:
    """Two principals draw from separate windows — one exhausting theirs does not
    limit the other."""
    quota = QuotaCounter(limit=1, window_seconds=86400.0)
    alice = keypair.sign(claims(sub="alice@example.test"))
    bob = keypair.sign(claims(sub="bob@example.test"))
    assert _call_codes(quota, keypair, alice, 2)[1] == QUOTA_CODE
    assert _call_codes(quota, keypair, bob, 1)[0] != QUOTA_CODE
