"""Integration test: a policy-denied tools/call is refused on the real path.

The point of this file is that enforcement fires where production sets the
principal — a real signed token through the real AuthenticationMiddleware, which
binds current_principal(), which on_call_tool reads. Nothing binds the principal
by hand; a test that did would exercise a path the gateway does not have (the
same lesson as tests/integration/test_no_passthrough.py).

Driven exactly like test_gateway_server.call_gateway: the SDK's streamable-HTTP
app starts its session-manager task group in the ASGI lifespan, so the request
runs inside app.router.lifespan_context or the app serves uninitialised.
"""

from __future__ import annotations

import contextlib
import json
import logging
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
from acp.observability.log import JsonFormatter
from acp.policy import Effect, Policy, Rule
from acp.policy.record import parse_traffic
from acp.policy.simulate import Outcome, simulate
from acp.upstream import UpstreamClient, UpstreamConfig

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}

# The default token's subject is alice@example.test (tests/tokens.py).
ALICE = "alice@example.test"


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
    """Read a JSON body, or the first data frame of an SSE stream."""
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


def call_tool(policy: Policy, keypair: Keypair, token: str, tool: str) -> dict[str, Any]:
    """POST one tools/call through the full gateway, policy enforced.

    Mirrors test_gateway_server.call_gateway: upstream clients entered, the SDK
    lifespan started (its task group), the Host the DNS-rebinding guard expects,
    and SSE-aware parsing.
    """
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"query": "x"}},
    }

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
                return _parse(response)
        raise AssertionError("unreachable")

    return anyio.run(_run)


def test_an_allowed_tool_call_reaches_the_upstream(keypair: Keypair) -> None:
    """A subject the policy allows for this tool is not refused by policy — the
    response carries no policy-denied error."""
    policy = Policy(
        rules=(
            Rule(
                name="allow-alice-search",
                effect=Effect.ALLOW,
                subjects=(ALICE,),
                tools=("mock-a__search",),
            ),
        )
    )
    token = keypair.sign(claims())
    result = call_tool(policy, keypair, token, "mock-a__search")
    if "error" in result:
        assert result["error"]["code"] != -32040, result


def test_a_denied_tool_call_is_refused_with_the_policy_code(keypair: Keypair) -> None:
    """An explicit deny returns the policy error code."""
    policy = Policy(
        rules=(Rule(name="deny-search", effect=Effect.DENY, tools=("mock-a__search",)),)
    )
    token = keypair.sign(claims())
    result = call_tool(policy, keypair, token, "mock-a__search")
    assert result["error"]["code"] == -32040


def test_deny_by_default_refuses_a_tool_no_rule_mentions(keypair: Keypair) -> None:
    """An empty policy denies everything — the deny default reaches the wire."""
    token = keypair.sign(claims())
    result = call_tool(Policy(), keypair, token, "mock-a__search")
    assert result["error"]["code"] == -32040


def test_the_denial_does_not_name_the_rule_on_the_wire(keypair: Keypair) -> None:
    """The refusal must not reveal which rule denied it, or that the tool exists
    — that would be an oracle. The rule is for the log, not the caller."""
    policy = Policy(rules=(Rule(name="deny-secret-rule-name", effect=Effect.DENY),))
    token = keypair.sign(claims())
    result = call_tool(policy, keypair, token, "mock-a__search")
    assert "deny-secret-rule-name" not in str(result)


# ---------------------------------------------------------------------------
# The decision log the simulator replays (task 38)
# ---------------------------------------------------------------------------


def decision_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The decision records, rendered exactly as a deployed gateway writes them."""
    return [
        JsonFormatter().format(record)
        for record in caplog.records
        if record.name == "acp.policy.enforce"
    ]


def test_the_gateway_writes_a_log_the_simulator_can_replay(
    keypair: Keypair, caplog: pytest.LogCaptureFixture
) -> None:
    """End to end: real request, real record, real replay — and it agrees.

    The unit tests prove `simulate` reasons correctly about a `Traffic` object.
    Only this proves the object exists: that a real request through the real
    middleware produces a record the reader parses, and that replaying it
    against the very policy that produced it reports no change. If it reported
    one, the simulator and the gateway would be disagreeing about a decision
    they both just made.
    """
    policy = Policy(
        rules=(
            Rule(
                name="allow-alice-search",
                effect=Effect.ALLOW,
                subjects=(ALICE,),
                tools=("mock-a__search",),
            ),
        )
    )
    token = keypair.sign(claims())

    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        call_tool(policy, keypair, token, "mock-a__search")

    traffic = parse_traffic(decision_lines(caplog))
    assert len(traffic.decisions) == 1
    assert traffic.unreadable == 0

    simulation = simulate(policy, traffic)
    assert simulation.safe
    assert simulation.counts[Outcome.UNCHANGED] == 1


def test_the_record_carries_the_arguments_the_request_actually_sent(
    keypair: Keypair, caplog: pytest.LogCaptureFixture
) -> None:
    """The call site, not the function.

    `_record` sorts whatever mapping it is handed; that is unit-tested. What is
    only observable here is that `on_call_tool` hands it the *request's*
    arguments rather than an empty dict — and an empty dict would still produce
    a valid-looking record, a green unit suite, and a simulator that reported
    every argument-scoped rule as inapplicable.
    """
    policy = Policy(rules=(Rule(name="allow-everything", effect=Effect.ALLOW),))
    token = keypair.sign(claims())

    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        call_tool(policy, keypair, token, "mock-a__search")

    traffic = parse_traffic(decision_lines(caplog))
    # `call_tool` sends {"query": "x"}.
    assert traffic.decisions[0].argument_names == frozenset({"query"})


def test_a_tightened_policy_is_reported_as_breaking_the_recorded_call(
    keypair: Keypair, caplog: pytest.LogCaptureFixture
) -> None:
    """The question the tool exists to answer, asked of real traffic."""
    live = Policy(
        rules=(
            Rule(
                name="allow-alice-search",
                effect=Effect.ALLOW,
                subjects=(ALICE,),
                tools=("mock-a__search",),
            ),
        )
    )
    proposed = Policy(
        rules=(Rule(name="no-search", effect=Effect.DENY, tools=("mock-a__search",)),)
    )
    token = keypair.sign(claims())

    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        call_tool(live, keypair, token, "mock-a__search")

    simulation = simulate(proposed, parse_traffic(decision_lines(caplog)))

    assert not simulation.safe
    assert simulation.counts[Outcome.NEWLY_DENIED] == 1
    assert "was: allow by allow-alice-search" in simulation.changed[0].describe()
