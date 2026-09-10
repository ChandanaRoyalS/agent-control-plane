"""Settings to a chained record — the assembly, not the parts.

`gateway_from_settings` has silently dropped new wiring five times. `acp.audit`
is fully unit-tested, and every one of those tests would still pass if the
gateway never called it — which is exactly the failure this file exists to catch.

So: a real request through the real middleware, and then the chain read back off
disk and verified. The unit tests prove the chain is a chain; only this proves
there is anything in it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from acp.audit import AuditLog, FileAuditSink, verify
from acp.audit.sink import MemoryAuditSink
from acp.config import GatewaySettings
from acp.exceptions import AuditUnavailableError
from acp.mocks import mock_a, mock_b
from acp.policy import Effect, Policy, Rule
from acp.runtime import build_audit_log
from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig

from ..tokens import Keypair, claims
from .helpers import authenticated_gateway, call_gateway, post_gateway

pytestmark = pytest.mark.integration

ALICE = "alice@example.test"
TOOL = "mock-a__search"

ALLOW = Policy(rules=(Rule(name="allow-alice", effect=Effect.ALLOW, subjects=(ALICE,)),))
DENY = Policy(rules=(Rule(name="deny-search", effect=Effect.DENY, tools=(TOOL,)),))


def settings_for(**overrides: Any) -> GatewaySettings:
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_required=False,
        health_probing_enabled=False,
        schema_drift_detection_enabled=False,
        **overrides,
    )


@pytest.fixture
def open_audit() -> Iterator[Callable[[Path], AuditLog]]:
    """A factory that closes every chain it opened.

    `FileAuditSink` holds its handle for the process's lifetime **on purpose** —
    reopening per write is slower and weaker, because it opens a window in which
    the path can be swapped between entries. The cost of that decision is that
    somebody has to close it.

    A test that walks away from one leaks a handle, and a `ResourceWarning`
    raised during garbage collection is *unraisable*: it surfaces on whichever
    unrelated test happens to be running when the collector fires. One leak here
    failed a tool-naming test three files away — a genuinely horrible thing to
    debug, and entirely avoidable by owning the lifetime in a fixture.
    """
    opened: list[FileAuditSink] = []

    def make(path: Path) -> AuditLog:
        sink = FileAuditSink(path, fsync=False)
        opened.append(sink)
        return AuditLog(sink)

    yield make
    for sink in opened:
        sink.close()


def records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line)["record"] for line in path.read_text().splitlines()]


# ---------------------------------------------------------------------------
# Settings to object
# ---------------------------------------------------------------------------


def test_no_path_means_no_chain(caplog: pytest.LogCaptureFixture) -> None:
    """Presence-based, and it says so — a deployment should be able to tell from
    the startup log which of the three audit states it is in."""
    with caplog.at_level(logging.INFO, logger="acp.runtime"):
        assert build_audit_log(settings_for()) is None

    assert [r for r in caplog.records if r.message == "audit.disabled"]


def test_a_configured_path_opens_a_chain(tmp_path: Path) -> None:
    audit = build_audit_log(settings_for(audit_file=tmp_path / "audit.jsonl", audit_fsync=False))

    assert audit is not None
    assert audit.required is True
    audit.close()


def test_the_chain_is_closed_with_everything_else(tmp_path: Path) -> None:
    """`gateway_from_settings` closes it beside the secret store, the exchanger
    and the key cache. It was the one resource in that `finally` that was
    missing, and nothing in production would ever have said so — the symptom
    surfaced in the test suite, on an unrelated file."""
    audit = build_audit_log(settings_for(audit_file=tmp_path / "audit.jsonl", audit_fsync=False))
    assert audit is not None

    audit.close()


def test_opting_out_of_fail_closed_is_loud(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The third state, and the one worth naming: a gateway that will keep
    serving calls it cannot record."""
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        audit = build_audit_log(
            settings_for(
                audit_file=tmp_path / "audit.jsonl", audit_required=False, audit_fsync=False
            )
        )
    assert audit is not None
    audit.close()

    [warned] = [r for r in caplog.records if r.message == "audit.not_required"]
    assert "gaps" in getattr(warned, "consequence", "")


# ---------------------------------------------------------------------------
# The request path actually writes
# ---------------------------------------------------------------------------


def test_an_allowed_call_is_chained(
    keypair: Keypair, tmp_path: Path, open_audit: Callable[[Path], AuditLog]
) -> None:
    """**The one the unit tests cannot reach.** Three records, because "alice
    was allowed to search", "the gateway dispatched it" and "it came back" are
    three different facts — and only the first two can be chained *before* they
    are true, which is what ADR 0050's claim requires and ADR 0067 restored."""
    path = tmp_path / "audit.jsonl"

    async def _run() -> None:
        async with authenticated_gateway(
            keypair, token=keypair.sign(claims()), policy=ALLOW, audit=open_audit(path)
        ) as agent:
            await call_gateway(agent, "tools/call", {"name": TOOL, "arguments": {"query": "x"}})

    anyio.run(_run)

    written = records(path)
    assert [r["category"] for r in written] == ["authorization", "tool_call", "tool_call"]
    assert written[0]["outcome"] == "allowed"
    # Chained before the upstream was touched: an unwritable record refuses the
    # call rather than leaving the side effect done and the chain silent.
    assert written[1]["outcome"] == "allowed"
    assert written[2]["outcome"] == "completed"


def test_the_chain_the_gateway_writes_verifies(
    keypair: Keypair, tmp_path: Path, open_audit: Callable[[Path], AuditLog]
) -> None:
    """End to end: what a real request produced is a chain the real verifier
    accepts. The two are separate modules and the format is all that holds them
    together."""
    path = tmp_path / "audit.jsonl"

    async def _run() -> None:
        async with authenticated_gateway(
            keypair, token=keypair.sign(claims()), policy=ALLOW, audit=open_audit(path)
        ) as agent:
            for index in range(3):
                await call_gateway(
                    agent, "tools/call", {"name": TOOL, "arguments": {"query": str(index)}}
                )

    anyio.run(_run)

    result = verify(path.read_text().splitlines())
    assert result.intact
    # Three per call: authorized, dispatched, completed (ADR 0067).
    assert result.entries == 9


def test_a_denial_is_chained(
    keypair: Keypair, tmp_path: Path, open_audit: Callable[[Path], AuditLog]
) -> None:
    """**The row an auditor actually wants.** A log containing only the calls
    that succeeded answers the wrong question."""
    path = tmp_path / "audit.jsonl"

    async def _run() -> None:
        async with authenticated_gateway(
            keypair, token=keypair.sign(claims()), policy=DENY, audit=open_audit(path)
        ) as agent:
            await post_gateway(agent, "tools/call", {"name": TOOL, "arguments": {"query": "x"}})

    anyio.run(_run)

    written = records(path)
    assert written, "a refused call left no trace"
    assert written[0]["outcome"] == "denied"
    assert written[0]["subject"] == ALICE


def test_the_record_carries_argument_names_and_not_values(
    keypair: Keypair, tmp_path: Path, open_audit: Callable[[Path], AuditLog]
) -> None:
    """ADR 0045's rule, on the durable artifact. A `doc_id` is as likely to be a
    patient record as a public page."""
    path = tmp_path / "audit.jsonl"

    async def _run() -> None:
        async with authenticated_gateway(
            keypair, token=keypair.sign(claims()), policy=ALLOW, audit=open_audit(path)
        ) as agent:
            await call_gateway(
                agent, "tools/call", {"name": TOOL, "arguments": {"query": "a patient name"}}
            )

    anyio.run(_run)

    body = path.read_text()
    assert "a patient name" not in body
    assert records(path)[0]["detail"]["argument_names"] == ["query"]


def test_a_gateway_with_no_audit_still_serves(keypair: Keypair) -> None:
    """The feature is optional, and its absence must not be a behaviour change
    anywhere else — every existing test in this suite runs without it."""

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(
            keypair, token=keypair.sign(claims()), policy=ALLOW
        ) as agent:
            return await call_gateway(
                agent, "tools/call", {"name": TOOL, "arguments": {"query": "x"}}
            )

    assert "error" not in anyio.run(_run)


# ---------------------------------------------------------------------------
# Fail-closed, on the real path
# ---------------------------------------------------------------------------


def test_a_call_that_cannot_be_recorded_is_refused(keypair: Keypair, tmp_path: Path) -> None:
    """**The guarantee, end to end.** Not that `AuditLog` raises — the unit
    tests prove that — but that the raise reaches the caller as a refusal rather
    than being swallowed somewhere in the request path."""

    class Broken:
        head = "0" * 64
        length = 0
        blocking = True
        """Required by the protocol since task 61, and `True` on purpose: this
        double exists to prove a failed write refuses the call, and that has to
        hold on the *threaded* path — the exception must cross the thread
        boundary to reach the caller."""

        def append(self, _record: Any) -> Any:
            raise OSError("no space left on device")

        def close(self) -> None:
            """Required by the protocol. See `test_writer.BrokenSink`."""

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(
            keypair,
            token=keypair.sign(claims()),
            policy=ALLOW,
            audit=AuditLog(Broken(), required=True),
        ) as agent:
            return await call_gateway(
                agent, "tools/call", {"name": TOOL, "arguments": {"query": "x"}}
            )

    payload = anyio.run(_run)

    assert payload["error"]["code"] == AuditUnavailableError.code
    assert "audit" not in json.dumps(payload).lower()


def test_a_call_that_cannot_be_recorded_never_reaches_the_upstream(
    keypair: Keypair,
) -> None:
    """**The half of the guarantee the refusal test does not cover.**

    ADR 0050's claim is that a call this gateway cannot record does not happen.
    The test above proves the *caller* is refused; it says nothing about whether
    the side effect already occurred, and until ADR 0067 it had. The tool-call
    record was chained after dispatch, so an unwritable record meant the
    upstream had run, the caller was told the call failed, and the chain was
    silent about the whole thing — the worst of the three outcomes.

    Counted at the transport and filtered to `tools/call`, so it observes the
    dispatch itself rather than the catalogue fetches the registry makes to
    resolve a name — those are the same URL and are not a side effect.
    """
    dispatched: list[str] = []

    def counting(app: Any) -> httpx.AsyncClient:
        async def transport(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content or b"{}")
            if body.get("method") == "tools/call":
                dispatched.append(str(body.get("params", {}).get("name")))
            inner = httpx.ASGITransport(app=app)
            return await inner.handle_async_request(request)

        return httpx.AsyncClient(transport=httpx.MockTransport(transport))

    class BrokenOnToolCall:
        head = "0" * 64
        length = 0
        blocking = True

        def append(self, record: Any) -> Any:
            # The authorization record is allowed through, so the failure lands
            # exactly on the write that guards dispatch.
            if str(record.category) == "tool_call":
                raise OSError("no space left on device")
            return MemoryAuditSink().append(record)

        def close(self) -> None:
            """Required by the protocol."""

    clients = [
        UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), counting(mock_a.app)),
        UpstreamClient(UpstreamConfig(name="mock-b", url="http://mock/mcp"), counting(mock_b.app)),
    ]

    async def _run() -> dict[str, Any]:
        async with authenticated_gateway(
            keypair,
            token=keypair.sign(claims()),
            policy=ALLOW,
            audit=AuditLog(BrokenOnToolCall(), required=True),
            clients=clients,
        ) as agent:
            return await call_gateway(
                agent, "tools/call", {"name": TOOL, "arguments": {"query": "x"}}
            )

    payload = anyio.run(_run)

    assert payload["error"]["code"] == AuditUnavailableError.code
    assert dispatched == [], f"the upstream was dispatched to anyway: {dispatched}"
