"""The gateway, driven by the official MCP Python client instead of by this suite.

Every other integration test speaks to the gateway through `helpers`, which
builds requests the way *this project* believes a client builds them. That is
a closed loop: the suite and the gateway agree because the same people wrote
both halves, and an external review of v2.0 named it as the gap (item 5) — no
test showed a client nobody here wrote could use the gateway.

So this file uses `mcp.client.Client`, the SDK's own high-level client, over
its own streamable-HTTP transport, with nothing from `helpers` on the wire:
no `EnvelopingTransport`, no hand-built envelope, no routing headers derived
here. The only thing the test supplies is a bearer token, because that is the
only thing a deployment's agent supplies. The transport is in-process
(`httpx2.ASGITransport`, the HTTP library the SDK itself uses), so the run is
offline and deterministic like the rest of the suite.

**What it found on the first run, which is why ADR 0072 exists:**

- A policy denial on the fast path (ADR 0043) answered `403 {"error":
  "forbidden"}`. The SDK cannot read that body, so the agent was told
  ``-32603 Server returned an error response`` — *the server broke, retry* —
  for a decision whose whole contract is ``recoverable: false``. The same
  denial from the handler said ``-32040``. Two answers to one decision, and the
  wrong one on the path a conforming client takes first.
- A `require_approval` call from a client that connected with the initialize
  handshake failed with ``-32603 Handler returned an invalid result``:
  `input_required` does not exist before 2026-07-28 and the SDK could not
  serialise it.

Both are fixed, and both are asserted below against what the real client
raises, not against a body this suite parsed.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp.client import InputRequiredRoundsExceededError
from mcp.shared.exceptions import MCPError
from mcp.types import InputRequiredResult, TextContent

from acp import __version__
from acp.approvals import InMemoryApprovalStore
from acp.audit import AuditLog, FileAuditSink
from acp.policy import Effect, Policy, Rule

from ..tokens import Keypair, claims
from .helpers import official_client

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

RUNBOOK = "runbooks/incident-2291.md"
PAYROLL = "hr/compensation-2026.md"

POLICY = Policy(
    rules=(
        Rule(
            name="not-payroll",
            effect=Effect.DENY,
            tools=("mock-a__read_document",),
            args={"path": (PAYROLL,)},
        ),
        Rule(name="no-channels", effect=Effect.DENY, tools=("mock-b__list_channels",)),
        Rule(
            name="tickets-need-a-person",
            effect=Effect.REQUIRE_APPROVAL,
            tools=("mock-a__create_ticket",),
        ),
        Rule(name="everything-else", effect=Effect.ALLOW),
    )
)
"""The README's shape: narrow restrictions in front of a broad allow."""


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def text(result: Any) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


@pytest.fixture
def token(keypair: Keypair) -> str:
    return keypair.sign(claims())


@pytest.fixture
def open_audit() -> Iterator[Callable[[Path], AuditLog]]:
    """Closes every chain it opened (see `test_audit_wiring.open_audit`)."""
    opened: list[FileAuditSink] = []

    def make(path: Path) -> AuditLog:
        sink = FileAuditSink(path, fsync=False)
        opened.append(sink)
        return AuditLog(sink)

    yield make
    for sink in opened:
        sink.close()


# ---------------------------------------------------------------------------
# Connecting and listing
# ---------------------------------------------------------------------------


async def test_the_client_negotiates_the_current_revision(keypair: Keypair, token: str) -> None:
    """`server/discover`, not the initialize handshake: the SDK's `auto` mode
    probes and only falls back for a legacy server."""
    async with official_client(keypair, token=token, policy=POLICY) as client:
        assert client.session.protocol_version == "2026-07-28"
        listed = await client.list_tools()

    assert listed.meta is not None
    assert listed.meta["io.modelcontextprotocol/serverInfo"] == {
        "name": "agent-control-plane",
        "version": __version__,
    }


async def test_the_client_sees_the_qualified_catalogue(keypair: Keypair, token: str) -> None:
    """Every tool namespaced by its upstream (ADR 0003), and a tool the policy
    denies outright is not in it at all (catalogue filtering)."""
    async with official_client(keypair, token=token, policy=POLICY) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}

    assert "mock-a__read_document" in names
    assert "mock-a__create_ticket" in names, "a gated tool must be visible to be asked for"
    assert "mock-b__list_channels" not in names
    assert all("__" in name for name in names)


async def test_a_permitted_call_comes_back_as_content(keypair: Keypair, token: str) -> None:
    async with official_client(keypair, token=token, policy=POLICY) as client:
        result = await client.call_tool("mock-a__read_document", {"path": RUNBOOK})

    assert not result.is_error
    assert "Incident 2291" in text(result)


async def test_with_no_token_the_client_cannot_connect(keypair: Keypair) -> None:
    """Authentication is in front of discovery too: there is no anonymous
    catalogue to probe."""
    with pytest.raises(BaseException) as raised:  # noqa: PT011
        async with official_client(keypair, token=None, policy=POLICY) as client:
            await client.list_tools()

    assert isinstance(raised.value, MCPError | BaseExceptionGroup)


# ---------------------------------------------------------------------------
# Refusals: what an agent built on the SDK is actually told
# ---------------------------------------------------------------------------


async def test_a_fast_path_denial_reaches_the_client_as_a_policy_refusal(
    keypair: Keypair, token: str
) -> None:
    """**The first finding.** The SDK sends `Mcp-Method`/`Mcp-Name`, so this
    denial is decided before the body is read (ADR 0043) — and the client must
    still be told *denied, do not retry*, not *server error*."""
    async with official_client(keypair, token=token, policy=POLICY) as client:
        with pytest.raises(MCPError) as raised:
            await client.call_tool("mock-b__list_channels", {})

    assert raised.value.error.code == -32040
    assert raised.value.error.data == {"recoverable": False}


async def test_both_layers_give_the_client_the_same_refusal(keypair: Keypair, token: str) -> None:
    """An argument-scoped deny cannot be decided from the headers, so the
    handler answers it. The two refusals must be indistinguishable to the
    agent; otherwise which layer fired is an oracle, and a retry policy keyed
    on the code behaves differently for one policy decision."""
    async with official_client(keypair, token=token, policy=POLICY) as client:
        with pytest.raises(MCPError) as fast:
            await client.call_tool("mock-b__list_channels", {})
        with pytest.raises(MCPError) as slow:
            await client.call_tool("mock-a__read_document", {"path": PAYROLL})

    assert fast.value.error == slow.value.error


async def test_a_respelled_restricted_value_is_still_refused(keypair: Keypair, token: str) -> None:
    """ADR 0068, through a client this project did not write."""
    async with official_client(keypair, token=token, policy=POLICY) as client:
        for variant in ("HR/Compensation-2026.md", f" {PAYROLL} ", PAYROLL.upper()):
            with pytest.raises(MCPError) as raised:
                await client.call_tool("mock-a__read_document", {"path": variant})
            assert raised.value.error.code == -32040, variant


# ---------------------------------------------------------------------------
# Approvals: the SDK's input_required loop meets a decision it cannot make
# ---------------------------------------------------------------------------


async def test_the_sdks_automatic_retries_cannot_approve_a_held_call(
    keypair: Keypair, token: str
) -> None:
    """`Client.call_tool` resolves `input_required` by itself, retrying with
    whatever the server asked for. The gateway asks for nothing the client can
    supply (ADR 0048), so the loop runs out — and the call it was retrying is
    held, once, for a person, not executed and not duplicated."""
    store = InMemoryApprovalStore()
    async with official_client(
        keypair, token=token, policy=POLICY, approvals=store, rounds=3
    ) as client:
        with pytest.raises(InputRequiredRoundsExceededError):
            await client.call_tool("mock-a__create_ticket", {"title": "leak"})

    pending = await store.pending()
    assert len(pending) == 1, "each retry carried the same requestState"


async def test_an_agent_that_waits_gets_the_call_once_a_person_approves(
    keypair: Keypair, token: str
) -> None:
    """The flow a real agent has to drive: ask once, hold the state, come back
    after the decision. `allow_input_required=True` is the SDK's way of letting
    the caller do the waiting instead of the loop."""
    store = InMemoryApprovalStore()
    async with official_client(keypair, token=token, policy=POLICY, approvals=store) as client:
        first = await client.session.call_tool(
            "mock-a__create_ticket", {"title": "rotate the key"}, allow_input_required=True
        )
        assert isinstance(first, InputRequiredResult)
        state = first.request_state
        assert state is not None

        [held] = await store.pending()
        await store.decide(held.token, approved=True)

        second = await client.session.call_tool(
            "mock-a__create_ticket",
            {"title": "rotate the key"},
            request_state=state,
            allow_input_required=True,
        )

    assert second.result_type == "complete"
    assert "rotate the key" in text(second)


async def test_a_handshake_era_client_is_refused_legibly_not_held(
    keypair: Keypair, token: str, tmp_path: Path, open_audit: Callable[[Path], AuditLog]
) -> None:
    """**The second finding.** A client on the initialize handshake cannot
    receive `input_required`, so the call is refused with a code that says so —
    before an approval exists for an operator to be asked about — and the chain
    records a refusal, not a hold."""
    store = InMemoryApprovalStore()
    path = tmp_path / "audit.jsonl"
    async with official_client(
        keypair,
        token=token,
        mode="legacy",
        policy=POLICY,
        approvals=store,
        audit=open_audit(path),
    ) as client:
        assert client.session.protocol_version != "2026-07-28"
        with pytest.raises(MCPError) as raised:
            await client.call_tool("mock-a__create_ticket", {"title": "leak"})

    assert raised.value.error.code == -32041
    assert raised.value.error.data == {"recoverable": False}
    assert await store.pending() == ()
    [decision] = [json.loads(line)["record"] for line in path.read_text().splitlines()]
    assert decision["category"] == "authorization"
    assert decision["outcome"] == "denied"


async def test_a_handshake_era_client_is_otherwise_served(keypair: Keypair, token: str) -> None:
    """The refusal above is about approvals only. Everything else works on the
    older handshake, and denials carry the same code there."""
    async with official_client(keypair, token=token, mode="legacy", policy=POLICY) as client:
        served = await client.call_tool("mock-a__read_document", {"path": RUNBOOK})
        with pytest.raises(MCPError) as raised:
            await client.call_tool("mock-b__list_channels", {})

    assert "Incident 2291" in text(served)
    assert raised.value.error.code == -32040


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


async def test_what_the_client_did_is_on_the_chain(
    keypair: Keypair, token: str, tmp_path: Path, open_audit: Callable[[Path], AuditLog]
) -> None:
    """A served call and a refused one, both written with the token's subject:
    the record does not depend on which client made the calls."""
    path = tmp_path / "audit.jsonl"
    async with official_client(
        keypair, token=token, policy=POLICY, audit=open_audit(path)
    ) as client:
        await client.call_tool("mock-a__read_document", {"path": RUNBOOK})
        with pytest.raises(MCPError):
            await client.call_tool("mock-a__read_document", {"path": PAYROLL})

    written = [json.loads(line)["record"] for line in path.read_text().splitlines()]
    outcomes = [(r["category"], r["outcome"]) for r in written]
    assert ("authorization", "allowed") in outcomes
    assert ("tool_call", "completed") in outcomes
    assert ("authorization", "denied") in outcomes
    assert {r["subject"] for r in written} == {claims()["sub"]}
