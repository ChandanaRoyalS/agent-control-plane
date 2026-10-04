#!/usr/bin/env python3
"""The model classifier on its own — what it sees, what it says, how long it takes.

    ollama serve   # or: brew services start ollama
    ollama pull llama3.2
    uv run python scripts/evaluate_classifier.py
    uv run python scripts/evaluate_classifier.py --repeats 3 --json classifier-run.json

`scripts/evaluate.py` with the classifier enabled scores the firewall, and the
patterns hide most of what the model does: a benign document the patterns
already flagged is flagged either way. This asks the model directly, with the
patterns out of the picture, and reports the five outcomes the firewall collapses
into two (see `acp.corpus.classifier_eval`).

Development split only. The held-out split is opened once, deliberately, by
`scripts/evaluate.py --unseal` (ADR 0041) — not by a second script that would
make reading it cheap.

Not a CI gate and never will be: the model is not in CI, and its answers vary.
Exit status is non-zero only when the model cannot be reached at all.
"""

from __future__ import annotations

import argparse
import functools
import json
import logging
import sys
from pathlib import Path

import httpx

from acp.corpus.classifier_eval import ClassifierReport, Outcome, evaluate_classifier
from acp.corpus.heldout import load_split
from acp.corpus.loader import load_benign
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion
from acp.firewall.ollama import (
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    ollama_classify,
)

UNREACHABLE = 2
RULE = "=" * 78
SEED = 20260812


def render(report: ClassifierReport, *, model: str, timeout: float) -> None:
    print(f"\n  model:    {model}  (timeout {timeout:g}s per call, as in production)")
    print(f"  repeats:  {report.repeats}  — rates are from run 1; later runs measure agreement\n")

    print("FALSE POSITIVES — benign documents, model alone")
    print(f"  became a finding        {report.benign_flagged.render()}")
    print(f"  model said 'attack'     {report.benign_said_attack.render()}")

    print("\nRECALL — by the family the corpus assigned")
    print(f"  {'family':<20} {'became a finding':<32} model said 'attack'")
    for row in report.recall:
        print(f"  {row.family.value:<20} {row.flagged.render():<32} {row.said_attack.render()}")

    print(f"\nEVERY CALL ({report.latency.calls})")
    for outcome in Outcome:
        print(f"  {outcome.value:<10} {report.outcomes[outcome]:>4}")
    if report.discarded_families:
        named = ", ".join(f"{k} x{v}" for k, v in report.discarded_families.items())
        print(f"  discarded because the model named: {named}")

    lat = report.latency
    print("\nLATENCY — per call, failures included")
    print(f"  median {lat.median:.2f}s   p95 {lat.p95:.2f}s   worst {lat.worst:.2f}s")

    if report.agreement is not None:
        print(f"\nAGREEMENT — same outcome in all {report.repeats} runs")
        print(f"  documents               {report.agreement.render()}")

    for title, ids in (
        ("BENIGN DOCUMENTS THE MODEL FLAGGED", report.benign_flagged_ids),
        ("ATTACKS THE MODEL CAUGHT BUT THE FIREWALL DISCARDED", report.attack_discarded_ids),
        ("DOCUMENTS WHOSE OUTCOME CHANGED BETWEEN RUNS", report.disagreeing_ids),
    ):
        if ids:
            print(f"\n{title} ({len(ids)})")
            for doc_id in ids:
                print(f"    {doc_id}")

    if report.warnings:
        print("\nREAD THIS BEFORE QUOTING ANY NUMBER ABOVE")
        for warning in report.warnings:
            print(f"  ! {warning}")


def to_json(report: ClassifierReport, *, model: str, timeout: float) -> str:
    """The run as a file, so a number quoted in an ADR has something to point at."""

    def prop(p: Proportion) -> dict[str, object]:
        return {
            "successes": p.successes,
            "total": p.total,
            "low": p.interval.low,
            "high": p.interval.high,
            "degenerate": p.interval.degenerate,
        }

    payload = {
        "model": model,
        "timeout_seconds": timeout,
        "repeats": report.repeats,
        "benign_flagged": prop(report.benign_flagged),
        "benign_said_attack": prop(report.benign_said_attack),
        "recall": {
            row.family.value: {
                "flagged": prop(row.flagged),
                "said_attack": prop(row.said_attack),
            }
            for row in report.recall
        },
        "outcomes": {k.value: v for k, v in report.outcomes.items()},
        "discarded_families": report.discarded_families,
        "latency_seconds": {
            "calls": report.latency.calls,
            "median": report.latency.median,
            "p95": report.latency.p95,
            "worst": report.latency.worst,
        },
        "agreement": prop(report.agreement) if report.agreement is not None else None,
        "benign_flagged_ids": list(report.benign_flagged_ids),
        "attack_discarded_ids": list(report.attack_discarded_ids),
        "disagreeing_ids": list(report.disagreeing_ids),
        "warnings": list(report.warnings),
    }
    return json.dumps(payload, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--json", type=Path, help="also write the run to this file")
    args = parser.parse_args()
    logging.disable(logging.WARNING)

    benign = load_benign().documents
    attacks = load_split().development.attacks

    with httpx.Client(timeout=args.timeout) as client:
        classify = functools.partial(
            ollama_classify, model=args.model, endpoint=args.endpoint, client=client
        )
        # The first call loads the model into memory, which can take longer than
        # the production timeout. Paid once, untimed, so the latency figures
        # describe a warm model — which is what a running gateway talks to.
        try:
            with httpx.Client(timeout=120.0) as warm:
                ollama_classify("warm-up", model=args.model, endpoint=args.endpoint, client=warm)
        except httpx.HTTPError as exc:
            print(
                f"FAILED: cannot reach {args.model} at {args.endpoint} ({exc}).\n"
                f"  Is Ollama running, and has `ollama pull {args.model}` finished?",
                file=sys.stderr,
            )
            return UNREACHABLE

        print(
            f"{RULE}\nCLASSIFIER ALONE — development split, {len(attacks)} attacks, "
            f"{len(benign)} benign documents\n{RULE}"
        )

        def progress(done: int, total: int) -> None:
            if done % 20 == 0 or done == total:
                print(f"  ... {done}/{total} calls", file=sys.stderr, flush=True)

        report = evaluate_classifier(
            classify,
            benign=benign,
            attacks=attacks,
            repeats=args.repeats,
            seed=args.seed,
            resamples=args.resamples,
            progress=progress,
        )

    render(report, model=args.model, timeout=args.timeout)
    if args.json:
        args.json.write_text(to_json(report, model=args.model, timeout=args.timeout), "utf-8")
        print(f"\nWrote {args.json}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
