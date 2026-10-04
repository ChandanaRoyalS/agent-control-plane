#!/usr/bin/env python3
"""The firewall against attacks nobody on this project wrote (InjecAgent).

    uv run python scripts/evaluate_external.py            # the development half
    uv run python scripts/evaluate_external.py --check    # CI: diff against the baseline
    uv run python scripts/evaluate_external.py --capture  # accept these counts
    uv run python scripts/evaluate_external.py --unseal   # ALSO score held-out v2
    ACP_FIREWALL_CLASSIFIER_ENABLED=1 uv run python scripts/evaluate_external.py

See `acp.corpus.external` for how the corpus is sliced and why intervals
resample attacker instructions, and ADR 0061 for the result. Three columns per
row, and the difference between the first two is the point:

- **flagged** — any finding, including ones the source's template produces with
  the attack removed;
- **caught** — a finding the template alone does not produce. This is recall;
- **withheld** — the firewall stopped the document.

Held-out v2 is half the attacker instructions, chosen by a hash. It is not
scored without `--unseal`, and like v1 (ADR 0060) it is scored once.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from acp.corpus.external import (
    ExternalReport,
    baseline_counts,
    compare_external,
    default_external_baseline,
    evaluate_external,
    load_external_split,
)
from acp.corpus.harness import DEFAULT_DEPLOYMENT, DEFAULT_SEED
from acp.corpus.metrics import DEFAULT_RESAMPLES
from acp.firewall import Firewall, OllamaClassifier
from acp.firewall.ollama import ollama_classify

CLASSIFIER_ENV = "ACP_FIREWALL_CLASSIFIER_ENABLED"
REGRESSED = 1
NOT_COMPARABLE = 2
RULE = "=" * 78


def build_firewall() -> tuple[Firewall, str]:
    classifier = None
    detectors = "deterministic patterns"
    if os.environ.get(CLASSIFIER_ENV):
        classifier = OllamaClassifier(classify_fn=ollama_classify)
        detectors += ", ollama classifier (MEDIUM-capped)"
    firewall = Firewall(
        enforce=True, allowed_hosts=DEFAULT_DEPLOYMENT.allowed_hosts, classifier=classifier
    )
    return firewall, detectors


def render(report: ExternalReport, *, title: str, detectors: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}\n")
    print(f"  deployment: {report.deployment}")
    print(f"  detectors:  {detectors}")
    print(f"  bootstrap:  {report.resamples:,} resamples over attacker instructions\n")
    print(f"  {'slice':<32} {'instr':>5}  {'caught (recall)':<30} {'flagged':<30} withheld")
    for row in report.rows:
        print(
            f"  {row.label:<32} {row.groups:>5}  {row.caught.render():<30} "
            f"{row.flagged.render():<30} {row.withheld.render()}"
        )
    caught_by = ", ".join(f"{k} x{v}" for k, v in report.reported_families.items()) or "nothing"
    print(f"\n  caught by:  {caught_by}")
    print(
        f"  template:   {report.template_flagged} control document(s) — the response with the\n"
        f"              attack removed — produced a finding on their own"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--check", action="store_true", help="fail on fewer caught or withheld")
    parser.add_argument("--capture", action="store_true", help="accept these counts")
    parser.add_argument("--unseal", action="store_true", help="ALSO score held-out v2")
    args = parser.parse_args()
    logging.disable(logging.WARNING)

    split = load_external_split()
    firewall, detectors = build_firewall()
    report = evaluate_external(
        firewall, split.development, seed=args.seed, resamples=args.resamples
    )
    render(
        report,
        title=f"INJECAGENT — development half, {len(split.development)} documents",
        detectors=detectors,
    )
    notice = (
        f"held-out split v{split.manifest.version}: {len(split.manifest)} instructions, "
        f"{len(split.heldout)} documents, "
    )
    if split.manifest.unsealed:
        print(f"\n  {notice}ALREADY UNSEALED ({split.manifest.unsealed})")
    else:
        print(f"\n  {notice}NOT SCORED (pass --unseal to score it)")

    if args.unseal and split.manifest.unsealed:
        version, when = split.manifest.version, split.manifest.unsealed
        print(f"\n{RULE}\n  HELD-OUT v{version} WAS ALREADY UNSEALED ({when}).")
        print("  These instructions are no longer unseen; what follows is not a")
        print(f"  generalisation estimate. Quote the recorded result.\n{RULE}")
    elif args.unseal:
        print(f"\n{RULE}\n  UNSEALING HELD-OUT v{split.manifest.version}.")
        print("  Record the result; do not tune against it. Then add")
        print(f"  `unsealed: <date>, <ADR>` to corpus/external/injecagent/heldout.txt.\n{RULE}")
        heldout = evaluate_external(
            firewall, split.heldout, seed=args.seed, resamples=args.resamples
        )
        render(
            heldout,
            title=f"HELD-OUT v{split.manifest.version} — {len(split.heldout)} documents",
            detectors=detectors,
        )

    path = default_external_baseline()
    if args.capture:
        path.write_text(json.dumps(baseline_counts(report), indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {path}. Commit it; the diff is the record of what you accepted.")
        return 0
    if not args.check:
        return 0

    comparison = compare_external(json.loads(path.read_text(encoding="utf-8")), report)
    for line in comparison.structural:
        print(f"  * {line}")
    for line in comparison.regressions:
        print(f"  ! {line}")
    for line in comparison.improvements:
        print(f"  + {line}")
    if comparison.structural:
        print("\nNOT COMPARABLE: re-capture so the diff records what changed.", file=sys.stderr)
        return NOT_COMPARABLE
    if comparison.regressions:
        print(f"\nFAILED: {len(comparison.regressions)} count(s) got worse.", file=sys.stderr)
        return REGRESSED
    print(f"\nNo regression against {path.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
