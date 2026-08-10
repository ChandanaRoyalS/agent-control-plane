"""Integration test: a caller over their rate limit is refused on the real path.

Built on the same lifespan-aware harness as the policy tests: a real token
through the real middleware sets the principal the limiter keys on. A small
bucket is exhausted, and the next call comes back as the rate-limit error.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.budget import RateLimiter
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

RATE_LIMIT_CODE = -32050


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


def _call_codes(limiter: RateLimiter, keypair: Keypair, token: str, n: int) -> list[int | None]:
    """Make n tools/call requests through the gateway; return each response's
    error code (or None for a successful result)."""
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
            UpstreamRegistry(clients), validator=_validator(keypair), limiter=limiter
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


def test_calls_within_the_burst_are_served_then_the_next_is_limited(keypair: Keypair) -> None:
    """A capacity-2 bucket serves two calls, then refuses the third with the
    rate-limit code — on the real authenticated path."""
    limiter = RateLimiter(capacity=2, refill_per_second=0.0)
    token = keypair.sign(claims())
    codes = _call_codes(limiter, keypair, token, 3)
    # First two are not rate-limited (None, or an upstream-level code — but never
    # the rate-limit code); the third is the rate-limit refusal.
    assert codes[0] != RATE_LIMIT_CODE
    assert codes[1] != RATE_LIMIT_CODE
    assert codes[2] == RATE_LIMIT_CODE


def test_the_limit_is_not_shared_between_callers(keypair: Keypair) -> None:
    """Two principals draw from separate buckets — one exhausting theirs does not
    limit the other."""
    limiter = RateLimiter(capacity=1, refill_per_second=0.0)
    alice = keypair.sign(claims(sub="alice@example.test"))
    bob = keypair.sign(claims(sub="bob@example.test"))
    # alice spends her one token, then is limited
    assert _call_codes(limiter, keypair, alice, 2)[1] == RATE_LIMIT_CODE
    # bob's first call is still served
    assert _call_codes(limiter, keypair, bob, 1)[0] != RATE_LIMIT_CODE
