#!/usr/bin/env python3
"""What the firewall actually does, measured — false positives first.

    uv run python scripts/evaluate.py                 # the development split
    uv run python scripts/evaluate.py --unseal        # opens the held-out split
    ACP_FIREWALL_CLASSIFIER_ENABLED=1 uv run python scripts/evaluate.py

Task 52. Every earlier number in this project was a count; these are estimates,
and they come with intervals because a rate over 106 documents and a rate over
106,000 read identically and are not the same claim.

**The held-out split is not scored unless you pass `--unseal`, and the flag is
loud on purpose.** The split's entire value is that nothing in it has influenced
a detector (ADR 0041). A harness that printed the held-out number on every run
would be read on every run, and by the third iteration of "that moved, let me
try something" the split has become a second development set wearing a label.
The seal is not a file permission; it is a habit, and the flag exists to make
breaking it a decision somebody made rather than a default they inherited.

The report still *names* the split and its size on every run, unsealed or not,
so the seal is visible in the artifact rather than asserted in a document nobody
opens.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from acp.corpus.harness import (
    DEFAULT_DEPLOYMENT,
    DEFAULT_SEED,
    Report,
    evaluate_firewall,
)
from acp.corpus.heldout import load_split
from acp.corpus.loader import load_benign
from acp.corpus.metrics import DEFAULT_RESAMPLES
from acp.firewall import Firewall, OllamaClassifier
from acp.firewall.ollama import ollama_classify

CLASSIFIER_ENV = "ACP_FIREWALL_CLASSIFIER_ENABLED"

RULE = "=" * 78


def build_firewall() -> tuple[Firewall, tuple[str, ...]]:
    """The firewall these numbers describe, and the detectors it carries.

    Enforce mode, because `withheld` is one of the two rates being measured and
    a firewall in report mode withholds nothing — the number would be a
    structural zero rather than a result.
    """
    classifier: OllamaClassifier | None = None
    detectors = ["deterministic patterns"]
    if os.environ.get(CLASSIFIER_ENV):
        classifier = OllamaClassifier(classify_fn=ollama_classify)
        detectors.append("ollama classifier (MEDIUM-capped)")
    firewall = Firewall(
        enforce=True,
        allowed_hosts=DEFAULT_DEPLOYMENT.allowed_hosts,
        classifier=classifier,
    )
    return firewall, tuple(detectors)


def render(report: Report, *, title: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}\n")
    print(f"  deployment: {report.deployment}")
    print(f"  detectors:  {', '.join(report.detectors)}")
    print(f"  bootstrap:  {report.resamples:,} resamples, seed {report.seed}\n")

    # First, and not as a courtesy. A firewall that stops legitimate documents
    # gets switched off, and a switched-off firewall's recall is zero.
    print("FALSE POSITIVES — benign documents, which nothing should happen to")
    print(f"  produced a finding   {report.false_positive_rate.render()}")
    print(f"  actually withheld    {report.benign_withheld_rate.render()}")

    print("\nRECALL — by the family the corpus assigned (what the attack IS)")
    print(f"  {'family':<20} {'any finding':<32} withheld")
    for row in report.recall:
        note = (
            f"  ({row.expected_undetected} expected undetected)" if row.expected_undetected else ""
        )
        print(f"  {row.family.value:<20} {row.detected.render():<32} {row.withheld.render()}{note}")

    print("\nPRECISION — by the family the firewall reported (what it SAID)")
    print(f"  {'family':<20} {'of what it flagged, real':<32} split")
    for prow in report.precision:
        print(
            f"  {prow.family.value:<20} {prow.precision.render():<32} "
            f"{prow.attack_hits} attack / {prow.benign_hits} benign"
        )

    if report.benign_flagged:
        print(f"\nBENIGN DOCUMENTS THAT TRIPPED A DETECTOR ({len(report.benign_flagged)})")
        print("  A rate says how often; only the list says what.")
        for doc_id in report.benign_flagged:
            print(f"    {doc_id}")

    if report.warnings:
        print("\nREAD THIS BEFORE QUOTING ANY NUMBER ABOVE")
        for warning in report.warnings:
            print(f"  ! {warning}")

    if report.all_mismatches:
        print(f"\nEXPECTATION MISMATCHES ({len(report.all_mismatches)})")
        print("  The corpus recorded a different outcome for these. A change in")
        print("  either direction is a behaviour change somebody has to acknowledge.")
        for attack_id in report.all_mismatches:
            print(f"    {attack_id}")

    print(f"\n  {report.heldout_notice}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument(
        "--unseal",
        action="store_true",
        help="ALSO score the held-out split. Not the default, on purpose — see ADR 0041.",
    )
    args = parser.parse_args()

    # The firewall logs a finding per detection at INFO. That is right on a
    # request path and useless here, where the whole point is the summary.
    logging.disable(logging.WARNING)

    benign = load_benign()
    split = load_split()
    firewall, detectors = build_firewall()

    sealed_notice = (
        f"held-out split v{split.version}: {len(split.heldout)} attacks, "
        f"NOT SCORED (pass --unseal to score it)"
    )
    report = evaluate_firewall(
        firewall,
        benign=benign,
        attacks=split.development,
        heldout_notice=sealed_notice,
        detectors=detectors,
        seed=args.seed,
        resamples=args.resamples,
    )
    development_title = (
        f"DEVELOPMENT SPLIT — {len(split.development)} attacks, {len(benign)} benign documents"
    )
    render(report, title=development_title)

    if args.unseal:
        print(f"\n{RULE}")
        print("  UNSEALING THE HELD-OUT SPLIT.")
        print("  These attacks have not shaped any detector. That is what makes")
        print("  the number below worth more than the one above — and it is also")
        print("  what reading it costs. Record the result; do not tune against it.")
        print(RULE)
        heldout = evaluate_firewall(
            firewall,
            benign=benign,
            attacks=split.heldout,
            heldout_notice=f"held-out split v{split.version}: SCORED, this run",
            detectors=detectors,
            seed=args.seed,
            resamples=args.resamples,
            scored_heldout=True,
        )
        render(heldout, title=f"HELD-OUT SPLIT v{split.version} — {len(split.heldout)} attacks")

    if report.all_mismatches:
        print(
            f"\nFAILED: {len(report.all_mismatches)} attack(s) did not do what the "
            f"corpus says they do.",
            file=sys.stderr,
        )
        return 1
    print("\nEvery attack behaved as the corpus records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
