"""The poisoned-description corpus behaves as recorded, and the benign one is clean.

`corpus/descriptions/poisoned.jsonl` is eight tool descriptions with an attack
in them, written by the person who wrote the detectors — so this is a behaviour
check, not a generalisation estimate (ADR 0065 says which is which). Each
records what the catalogue screen is expected to do, including `undetected`, and
a change in either direction fails here.

The benign half is the one that was not written here: every description in
InjecAgent's 330-tool catalogue, which the screen must leave alone.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.corpus.external import default_external_dir
from acp.corpus.harness import DEFAULT_DEPLOYMENT
from acp.corpus.loader import default_root
from acp.firewall import Firewall
from acp.upstream.models import ToolDefinition

pytestmark = pytest.mark.integration

POISONED = default_root() / "descriptions" / "poisoned.jsonl"


def rows(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def outcome(firewall: Firewall, tool: ToolDefinition, catalogue: frozenset[str]) -> str:
    inspection = firewall.inspect_tool(tool, tools=catalogue)
    if inspection.withheld:
        return "withheld"
    return "detected" if inspection.screening.findings else "undetected"


def test_every_poisoned_description_does_what_the_corpus_records() -> None:
    firewall = Firewall(enforce=True, allowed_hosts=DEFAULT_DEPLOYMENT.allowed_hosts)
    poisoned = rows(POISONED)
    assert len(poisoned) >= 8
    tools = [ToolDefinition.model_validate(r["tool"]) for r in poisoned]
    catalogue = frozenset(t.name for t in tools) | DEFAULT_DEPLOYMENT.catalogue
    mismatches = [
        (r["id"], r["expect"], got)
        for r, tool in zip(poisoned, tools, strict=True)
        if (got := outcome(firewall, tool, catalogue)) != r["expect"]
    ]
    assert mismatches == []


def test_the_corpus_covers_withheld_detected_and_undetected() -> None:
    """Anti-filler: a corpus where everything is caught, or nothing is held,
    would pass the test above and prove less than it looks."""
    expectations = {str(r["expect"]) for r in rows(POISONED)}
    assert expectations == {"withheld", "detected", "undetected"}


def test_no_external_tool_description_is_flagged() -> None:
    """1,096 descriptions nobody here wrote: zero findings, zero withheld.
    This is the false-positive measurement that let the screen enforce."""
    firewall = Firewall(enforce=True, allowed_hosts=DEFAULT_DEPLOYMENT.allowed_hosts)
    benign = rows(default_external_dir() / "descriptions.jsonl")
    assert len(benign) > 1000
    catalogue = frozenset(str(r["id"]) for r in benign)
    flagged = [
        r["id"]
        for r in benign
        if firewall.inspect_tool(
            ToolDefinition(name=str(r["id"]), description=str(r["text"])), tools=catalogue
        ).screening.findings
    ]
    assert flagged == []
