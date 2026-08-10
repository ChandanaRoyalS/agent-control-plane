"""Integration test: a costly tool draws more budget on the real request path.

Reuses the task-38 rate-limiting harness — real token, real middleware, a
principal keyed by subject — and gives the limiter a cost table that makes one
tool expensive, so the bucket empties in fewer calls than its capacity.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.budget import CostTable, RateLimiter
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


def _call_codes(
    limiter: RateLimiter, costs: CostTable, keypair: Keypair, token: str, n: int
) -> list[int | None]:
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
            UpstreamRegistry(clients),
            validator=_validator(keypair),
            limiter=limiter,
            costs=costs,
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


def test_a_costly_tool_exhausts_the_budget_sooner(keypair: Keypair) -> None:
    """With mock-a__search costing 5 and a capacity-10 bucket, the third call is
    refused — cost weighting reaches the real request path."""
    limiter = RateLimiter(capacity=10, refill_per_second=0.0)
    costs = CostTable(costs={"mock-a__search": 5.0})
    token = keypair.sign(claims())
    codes = _call_codes(limiter, costs, keypair, token, 3)
    assert codes[0] != RATE_LIMIT_CODE
    assert codes[1] != RATE_LIMIT_CODE
    assert codes[2] == RATE_LIMIT_CODE


def test_the_default_cost_leaves_task_38_behaviour_unchanged(keypair: Keypair) -> None:
    """An empty cost table charges one per call, so a capacity-2 bucket still
    serves two then refuses the third — exactly as rate limiting alone did."""
    limiter = RateLimiter(capacity=2, refill_per_second=0.0)
    costs = CostTable()
    token = keypair.sign(claims())
    codes = _call_codes(limiter, costs, keypair, token, 3)
    assert codes[2] == RATE_LIMIT_CODE
    assert codes[0] != RATE_LIMIT_CODE
