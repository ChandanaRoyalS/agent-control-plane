#!/usr/bin/env python3
"""What the detectors do to tool descriptions nobody here wrote.

    uv run python scripts/evaluate_descriptions.py

Before the catalogue screen was allowed to withhold a tool (ADR 0065), the same
detectors were run over every description in InjecAgent's 330-tool catalogue —
38 toolkit descriptions, 330 tool summaries, 728 parameter descriptions, as
their authors wrote them — plus this project's own six mock tools. None of
these is an attack, so every finding is a false positive and every trigger is a
tool a deployment would have lost from its catalogue.

Pattern detectors only, the same configuration `evaluate.py` uses, each text
screened as one tool with the full catalogue as "others".
"""

from __future__ import annotations

import json
from collections import Counter

from acp.corpus.external import default_external_dir
from acp.corpus.harness import DEFAULT_DEPLOYMENT
from acp.firewall import Firewall
from acp.firewall.decision import triggers_for
from acp.mocks import mock_a, mock_b
from acp.upstream.models import ToolDefinition

RULE = "=" * 78


def external() -> list[tuple[str, str, ToolDefinition]]:
    path = default_external_dir() / "descriptions.jsonl"
    rows: list[tuple[str, str, ToolDefinition]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        rows.append(
            (row["id"], row["kind"], ToolDefinition(name=row["id"], description=row["text"]))
        )
    return rows


def mocks() -> list[tuple[str, str, ToolDefinition]]:
    rows: list[tuple[str, str, ToolDefinition]] = []
    for upstream, tools in (("mock-a", mock_a.TOOLS), ("mock-b", mock_b.TOOLS)):
        for tool in tools:
            definition = tool.definition().model_copy(update={"name": f"{upstream}__{tool.name}"})
            rows.append((definition.name, "mock", definition))
    return rows


def main() -> int:
    firewall = Firewall(enforce=True, allowed_hosts=DEFAULT_DEPLOYMENT.allowed_hosts)
    population = external() + mocks()
    catalogue = frozenset(name for name, _, _ in population)

    by_kind: Counter[str] = Counter()
    flagged_by_kind: Counter[str] = Counter()
    by_detector: Counter[str] = Counter()
    withheld: list[str] = []
    flagged: list[tuple[str, str]] = []
    for name, kind, tool in population:
        by_kind[kind] += 1
        inspection = firewall.inspect_tool(tool, tools=catalogue)
        if inspection.screening.findings:
            flagged_by_kind[kind] += 1
            flagged.append(
                (name, ", ".join(sorted({f.detector for f in inspection.screening.findings})))
            )
            for finding in inspection.screening.findings:
                by_detector[finding.detector] += 1
        if triggers_for(inspection.screening):
            withheld.append(name)

    print(
        f"{RULE}\nTOOL DESCRIPTIONS — {len(population)} benign texts, pattern detectors\n{RULE}\n"
    )
    print(f"  {'kind':<10} {'texts':>6}  {'flagged':>8}")
    for kind in ("toolkit", "tool", "parameter", "mock"):
        print(f"  {kind:<10} {by_kind[kind]:>6}  {flagged_by_kind[kind]:>8}")
    total_flagged = sum(flagged_by_kind.values())
    print(f"\n  flagged (any finding)   {total_flagged} / {len(population)}")
    print(f"  WOULD BE WITHHELD       {len(withheld)} / {len(population)}")
    if by_detector:
        print("\n  findings by detector")
        for detector, count in by_detector.most_common():
            print(f"    {detector:<24} {count}")
    if flagged:
        print(f"\nFLAGGED DESCRIPTIONS ({len(flagged)})")
        for name, detectors in flagged:
            print(f"    {name}  [{detectors}]")
    if withheld:
        print(f"\nWITHHELD ({len(withheld)}) — each is a legitimate tool a deployment would lose")
        for name in withheld:
            print(f"    {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
