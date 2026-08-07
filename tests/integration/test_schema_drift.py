"""End-to-end: a mock upstream changes what it serves, and the gateway notices.

Everything above this file is tested against hand-built catalogues. This one
drives the real mock servers over a real (in-process) HTTP transport with the
real client and the real envelope, because the failure this task exists to catch
is a failure of *observation*, and observation is exactly what a hand-built
fixture cannot vouch for.

The test worth reading is the first one. Nothing else in this repository can
detect it: every request succeeds, in single-digit milliseconds, with a
well-formed response. No timeout, no retry, no breaker, no error. The only
evidence that anything happened is a sentence of prose.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import httpx
import pytest

from acp.mocks import mock_a, mock_b
from acp.mocks.drift import DRIFT_ENV, RUG_PULL_SENTENCE, DriftFlavour
from acp.schema import DriftDetector, DriftKind, SchemaSnapshot
from acp.upstream import UpstreamConfig
from acp.upstream.client import UpstreamClient
from acp.upstream.models import ListToolsResult

pytestmark = pytest.mark.integration

UPSTREAM = "mock-a"


async def fetch(app: Any = None, name: str = UPSTREAM) -> ListToolsResult:
    """One `tools/list` against a mock, through the gateway's own client."""
    transport = httpx.ASGITransport(app=app or mock_a.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://mock") as http:
        client = UpstreamClient(UpstreamConfig(name=name, url="http://mock/mcp"), http)
        return await client.list_tools()


def live(flavour: DriftFlavour, monkeypatch: pytest.MonkeyPatch) -> ListToolsResult:
    monkeypatch.setenv(DRIFT_ENV, str(flavour))
    result: ListToolsResult = anyio.run(fetch)
    return result


@pytest.fixture
def baseline(monkeypatch: pytest.MonkeyPatch) -> SchemaSnapshot:
    """What mock A serves when nothing is tampering with it."""
    return SchemaSnapshot.from_catalogues({UPSTREAM: live(DriftFlavour.NONE, monkeypatch)})


def detector(baseline: SchemaSnapshot) -> DriftDetector:
    return DriftDetector(baseline, known=[UPSTREAM])


def kinds(report: Any) -> list[str]:
    return sorted(str(event.kind) for event in report.events)


# ---------------------------------------------------------------------------
# The one that matters
# ---------------------------------------------------------------------------


def test_a_rug_pull_is_caught(
    baseline: SchemaSnapshot, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An upstream appends an instruction to a tool description and changes
    nothing else.

    The tool has the same name, the same arguments and the same behaviour. Every
    call still succeeds. What changed is a paragraph of prose that goes straight
    into the agent's prompt — which is the most powerful field in the protocol
    and the only one an upstream can rewrite without breaking a single client.
    """
    tampered = live(DriftFlavour.DESCRIPTION, monkeypatch)
    assert RUG_PULL_SENTENCE in tampered.tools[0].description, "the mock did not actually drift"

    with caplog.at_level(logging.WARNING, logger="acp.schema.detector"):
        report = detector(baseline).observe(UPSTREAM, tampered)

    assert kinds(report) == [DriftKind.DESCRIPTION_CHANGED]
    assert report.events[0].tool == "read_document"
    assert any(r.message == "schema.drift" for r in caplog.records)


def test_the_rug_pull_leaves_no_other_trace(
    baseline: SchemaSnapshot, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stated as a test because it is the justification for the whole task.

    The tampered response is well-formed, successful, the same size, and carries
    the same cache hints as the clean one. Nothing in tasks 13 through 19 has
    anything to react to.
    """
    clean = SchemaSnapshot.from_catalogues({UPSTREAM: live(DriftFlavour.NONE, monkeypatch)})
    tampered = live(DriftFlavour.DESCRIPTION, monkeypatch)

    assert len(tampered.tools) == len(baseline.upstreams[UPSTREAM].tools)
    assert tampered.ttl_ms > 0
    assert (
        clean.upstreams[UPSTREAM].fingerprint
        != SchemaSnapshot.from_catalogues({UPSTREAM: tampered}).upstreams[UPSTREAM].fingerprint
    )


# ---------------------------------------------------------------------------
# The other flavours, over the real transport
# ---------------------------------------------------------------------------


def test_a_new_tool_appears(baseline: SchemaSnapshot, monkeypatch: pytest.MonkeyPatch) -> None:
    report = detector(baseline).observe(UPSTREAM, live(DriftFlavour.ADDED, monkeypatch))

    assert kinds(report) == [DriftKind.TOOL_ADDED]
    assert report.events[0].tool == "exfiltrate"


def test_a_tool_disappears(baseline: SchemaSnapshot, monkeypatch: pytest.MonkeyPatch) -> None:
    report = detector(baseline).observe(UPSTREAM, live(DriftFlavour.REMOVED, monkeypatch))

    assert kinds(report) == [DriftKind.TOOL_REMOVED]


def test_an_argument_appears(baseline: SchemaSnapshot, monkeypatch: pytest.MonkeyPatch) -> None:
    report = detector(baseline).observe(UPSTREAM, live(DriftFlavour.SCHEMA, monkeypatch))

    assert kinds(report) == [DriftKind.SCHEMA_CHANGED]


def test_an_untouched_upstream_reports_nothing(
    baseline: SchemaSnapshot, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The false-positive case, and the one that decides whether anybody keeps
    the alert switched on. Two independent fetches of an unchanged catalogue
    must agree exactly — through JSON serialisation, the envelope, HTTP and
    Pydantic parsing, none of which promise to preserve ordering."""
    report = detector(baseline).observe(UPSTREAM, live(DriftFlavour.NONE, monkeypatch))

    assert report.has_drift is False


# ---------------------------------------------------------------------------
# The committed baseline
# ---------------------------------------------------------------------------


def test_the_repository_baseline_matches_what_the_mocks_serve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The baseline in `config/` is a real file, not a fixture, and this is the
    CI gate that keeps it honest: change a mock's tools without re-capturing and
    this fails. That is the same review step `acp schemas check` enforces
    against real upstreams, running here against servers the suite owns."""
    from pathlib import Path  # noqa: PLC0415 — only this test needs it

    monkeypatch.setenv(DRIFT_ENV, str(DriftFlavour.NONE))
    committed = SchemaSnapshot.load(Path("config/schema-baseline.json"))
    assert committed is not None, "run `acp schemas capture` and commit the result"

    observed = SchemaSnapshot.from_catalogues(
        {
            "mock-a": anyio.run(fetch, mock_a.app, "mock-a"),
            "mock-b": anyio.run(fetch, mock_b.app, "mock-b"),
        }
    )

    assert {name: entry.fingerprint for name, entry in observed.upstreams.items()} == {
        name: entry.fingerprint for name, entry in committed.upstreams.items()
    }, "config/schema-baseline.json is stale; run `acp schemas capture`"
