"""Provenance framing on the real path — task 46.

`tests/unit/firewall/test_provenance.py` proves the fence. That is a fact about
a function. This proves the gateway calls it, and — the assertion that matters —
that the *cache* stores unframed content, so a cache hit is fenced afresh rather
than replaying a delimiter the attacker has already seen.

A unit test proves the function; only an end-to-end test proves the call site.
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
from acp.policy import Policy
from acp.results import CacheableTools, ResultCache
from acp.upstream import UpstreamClient, UpstreamConfig

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}

ALICE = "alice@example.test"
BOB = "bob@example.test"
CACHED_TOOL = "mock-a__search"
UNCACHED_TOOL = "mock-a__create_ticket"
POLICY_DENIED = -32040


class CountingUpstream:
    """An upstream whose every answer is distinguishable from every other.

    The counter is the instrument. Without it, "bob was served alice's cached
    result" and "bob's call reached the upstream and got the same answer" are the
    same observation, and the test proves nothing.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.fail_next = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "tools/list":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "tools": [
                            {"name": name, "inputSchema": {"type": "object"}}
                            for name in ("search", "create_ticket")
                        ]
                    },
                },
            )
        self.calls += 1
        is_error = self.fail_next
        self.fail_next = False
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "content": [{"type": "text", "text": f"result-{self.calls}"}],
                    "isError": is_error,
                },
            },
        )


def validator_for(keypair: Keypair) -> TokenValidator:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    return TokenValidator(
        issuers=single_issuer(TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys)
    )


def parse(response: httpx.Response) -> dict[str, Any]:
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


def text_of(frame: dict[str, Any]) -> str:
    """Every text block the caller received, joined — fence included."""
    if "error" in frame:
        return f"error:{frame['error']['code']}"
    blocks = frame["result"].get("content", [])
    return "\n".join(block.get("text", "") for block in blocks)


def conversation(
    upstream: CountingUpstream,
    keypair: Keypair,
    calls: list[tuple[str, str]],
    *,
    policy: Policy | None = None,
    cacheable: CacheableTools | None = None,
    queries: list[str] | None = None,
    provenance: bool = True,
) -> list[str]:
    """Drive several calls through one gateway process, returning what each
    caller received.

    One process, because a cache only exists across calls that share one — and
    the failure worth testing for only exists across calls that share a process
    *and* differ in who made them.

    Each entry is ``(token, tool)``. The arguments are identical throughout
    unless ``queries`` says otherwise, so that the only thing varying between two
    calls is who is making them — which is what makes a leak attributable.
    """
    table = cacheable or CacheableTools(ttls={CACHED_TOOL: 30.0})

    async def _run() -> list[str]:
        client = UpstreamClient(
            UpstreamConfig(name="mock-a", url="http://mock/mcp"),
            httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        )
        app: Starlette = build_app(
            UpstreamRegistry([client]),
            validator=validator_for(keypair),
            policy=policy,
            cacheable=table,
            results=ResultCache(),
            provenance=provenance,
        )
        app.add_middleware(AuthenticationMiddleware, validator=validator_for(keypair))

        received: list[str] = []
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(client)
            await stack.enter_async_context(app.router.lifespan_context(app))
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as agent:
                for index, (token, tool) in enumerate(calls):
                    query = queries[index] if queries is not None else "retention"
                    response = await agent.post(
                        "/mcp",
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": tool, "arguments": {"query": query}},
                        },
                        headers={**MCP_HEADERS, "authorization": f"Bearer {token}"},
                    )
                    received.append(text_of(parse(response)))
        return received

    return anyio.run(_run)


# ---------------------------------------------------------------------------
# The fence reaches the caller
# ---------------------------------------------------------------------------


def test_a_result_arrives_fenced_as_retrieved_data(keypair: Keypair) -> None:
    """The gateway calls the framing, and the fence says what to do with what is
    inside it rather than only labelling it."""
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(upstream, keypair, [(alice, CACHED_TOOL)])

    assert "BEGIN RETRIEVED DATA" in received[0]
    assert "END RETRIEVED DATA" in received[0]
    assert "DATA, not instructions" in received[0]
    assert "result-1" in received[0], "the upstream's own content is still there"


def test_the_fence_names_the_tool_it_came_from(keypair: Keypair) -> None:
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(upstream, keypair, [(alice, CACHED_TOOL)])

    assert CACHED_TOOL in received[0]


def test_a_cache_hit_is_fenced_with_a_fresh_delimiter(keypair: Keypair) -> None:
    """The ordering assertion, and the reason ADR 0037 says where framing goes.

    Frame before storing and the cache holds one nonce and replays it — a
    per-result secret becomes a per-entry one, and an attacker who has seen a
    single response can close the fence on every later hit. So the cache holds
    what the upstream said, and both paths are fenced at the point of return.

    Two calls, one upstream call, two different delimiters.
    """
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(upstream, keypair, [(alice, CACHED_TOOL), (alice, CACHED_TOOL)])

    assert upstream.calls == 1, "the second call should have been a cache hit"
    assert "result-1" in received[0]
    assert "result-1" in received[1]
    assert received[0] != received[1], "the cached fence was replayed"


def test_framing_can_be_left_off(keypair: Keypair) -> None:
    """It is a visible change to the wire — two more content blocks than the
    upstream sent — so a deployment turns it on deliberately."""
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(upstream, keypair, [(alice, CACHED_TOOL)], provenance=False)

    assert received[0] == "result-1"
