"""Integration test: a policy-denied tools/call is refused on the real path.

The point of this file is that enforcement fires where production sets the
principal — a real signed token through the real AuthenticationMiddleware, which
binds current_principal(), which on_call_tool reads. Nothing binds the principal
by hand; a test that did would exercise a path the gateway does not have (the
same lesson as tests/integration/test_no_passthrough.py).

Driven through `helpers.authenticated_gateway`: the SDK's streamable-HTTP app
starts its session-manager task group in the ASGI lifespan, so the request runs
inside it or the app serves uninitialised.

**A denial has two layers, and until task 55 this file only ever tested one of
them.** The requests here were hand-rolled and carried no `Mcp-Method` or
`Mcp-Name`, so the pre-dispatch check (ADR 0043) had nothing to authorize on and
abstained every time — every assertion below landed on `enforce_call`, the
backstop. Sending valid requests changed which layer answers, and the deny tests
started failing with `TypeError: string indices must be integers`: the refusal
was no longer a JSON-RPC error object but an HTTP 403 with `{"error":
"forbidden"}`, exactly as `_refuse` is written to answer.

**That was the tests being wrong, not the gateway** — and it is the finding, not
the inconvenience. A real client sending a valid request is refused at the
header, before a body is read, and nothing in this suite had ever asserted what
that client receives. So the denials below are now split: the ones the fast path
can prove, and the one it must abstain on because the rule constrains an
argument nobody has read yet. Both layers, each asserted where it actually
answers.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import httpx
import pytest

from acp.observability.log import JsonFormatter
from acp.policy import Effect, Policy, Rule
from acp.policy.record import parse_traffic
from acp.policy.simulate import Outcome, simulate

from ..tokens import Keypair, claims
from .helpers import authenticated_gateway, call_gateway, parse_rpc, post_gateway

pytestmark = pytest.mark.integration

# The default token's subject is alice@example.test (tests/tokens.py).
ALICE = "alice@example.test"

TOOL = "mock-a__search"
ARGUMENTS = {"query": "x"}


def post_tool(
    policy: Policy,
    keypair: Keypair,
    token: str,
    tool: str,
    arguments: dict[str, Any] | None = None,
) -> httpx.Response:
    """POST one tools/call through the full gateway and return the response.

    Unparsed, because which layer refused is visible in the status code and
    nowhere else: 403 is the pre-dispatch check answering before a body is read,
    and 200-carrying-a-JSON-RPC-error is `enforce_call` answering after.
    """

    async def _run() -> httpx.Response:
        async with authenticated_gateway(keypair, token=token, policy=policy) as agent:
            return await post_gateway(
                agent,
                "tools/call",
                {"name": tool, "arguments": ARGUMENTS if arguments is None else arguments},
            )

    return anyio.run(_run)


def call_tool(policy: Policy, keypair: Keypair, token: str, tool: str) -> dict[str, Any]:
    """The same call, parsed, for the assertions that are about the payload."""

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(keypair, token=token, policy=policy) as agent:
            return await call_gateway(agent, "tools/call", {"name": tool, "arguments": ARGUMENTS})

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


def test_a_denied_tool_call_is_refused_before_its_body_is_read(keypair: Keypair) -> None:
    """The layer a real denied client actually meets.

    An explicit deny naming the tool is provable from the routing headers alone,
    so the pre-dispatch check refuses it and the JSON-RPC handler never runs.
    403 rather than a JSON-RPC error inside a 200, for the reason
    `AuthenticationMiddleware` returns 401: this happens before anything parses
    a body, and answering 200 tells every proxy in the path that the request
    succeeded.
    """
    policy = Policy(rules=(Rule(name="deny-search", effect=Effect.DENY, tools=(TOOL,)),))

    response = post_tool(policy, keypair, keypair.sign(claims()), TOOL)

    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}


def test_deny_by_default_is_refused_at_the_header_too(keypair: Keypair) -> None:
    """An empty policy denies everything, and "everything" is provable without a
    body — so the deny default reaches the wire from the fast path."""
    response = post_tool(Policy(), keypair, keypair.sign(claims()), TOOL)

    assert response.status_code == 403


def test_a_call_the_fast_path_cannot_decide_is_refused_by_the_backstop(
    keypair: Keypair,
) -> None:
    """**The test this file was missing.**

    ADR 0043's whole safety argument is that the pre-check may refuse and may
    never authorize, with `enforce_call` remaining authoritative — and nothing
    here had ever exercised the second half on a *denial*, because every request
    was under-specified enough that the fast path abstained on all of them.

    The only allow is argument-scoped, so at header time the answer genuinely
    depends on a body nobody has read: `could_ever_allow` says "not provably
    refused" and stands aside. The call reaches `enforce_call`, whose arguments
    do not match, and is denied by the default — as a JSON-RPC error with the
    policy code, inside a 200.

    A `require_approval` rule would be abstained on for the same reason, which
    is why a gated call is never falsely refused at the header.
    """
    policy = Policy(
        rules=(
            Rule(
                name="allow-one-query",
                effect=Effect.ALLOW,
                subjects=(ALICE,),
                tools=(TOOL,),
                args={"query": ("permitted",)},
            ),
        )
    )

    response = post_tool(policy, keypair, keypair.sign(claims()), TOOL, {"query": "something else"})

    # Not 403 is the load-bearing half: this call was *not* refused at the
    # header. The status of a JSON-RPC error is the SDK's business; which layer
    # answered is this project's.
    assert response.status_code != 403, response.text
    assert parse_rpc(response)["error"]["code"] == -32040


def test_neither_refusal_names_the_rule_on_the_wire(keypair: Keypair) -> None:
    """The refusal must not reveal which rule denied it, or that the tool exists
    — that would be an oracle. Asserted on **both** layers, because they are two
    different pieces of code writing two different bodies, and an oracle added to
    either one is an oracle."""
    fast = Policy(rules=(Rule(name="deny-secret-rule-name", effect=Effect.DENY),))
    backstop = Policy(
        rules=(
            Rule(
                name="allow-secret-rule-name",
                effect=Effect.ALLOW,
                tools=(TOOL,),
                args={"query": ("permitted",)},
            ),
        )
    )
    token = keypair.sign(claims())

    refused_early = post_tool(fast, keypair, token, TOOL)
    refused_late = post_tool(backstop, keypair, token, TOOL, {"query": "something else"})

    assert "secret-rule-name" not in refused_early.text
    assert "secret-rule-name" not in refused_late.text


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
