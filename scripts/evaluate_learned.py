#!/usr/bin/env python3
"""Score the learned classifier beside the pattern firewall (ADR 0075).

    uv run python scripts/evaluate_learned.py            # validation and report-only sets
    uv run python scripts/evaluate_learned.py --unseal   # the sealed sets, once

Writes `corpus/learned/results.json`. The sealed section (BIPIA test, evasion v1)
is written once and never overwritten: `--unseal` refuses if it is already there.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

from acp.corpus.bipia import load_bipia
from acp.corpus.learned_eval import Row, as_json, compare
from acp.corpus.loader import default_root
from acp.corpus.training import Example, assemble
from acp.firewall.learned import MODEL_PATH, load_model

RESULTS = default_root() / "learned" / "results.json"


def show(rows: list[Row]) -> None:
    print(
        f"{'set':<30} {'':<8} {'learned: report':<33} {'learned: enforce':<33} "
        f"{'patterns: any finding':<33} patterns: withheld"
    )
    for r in rows:
        print(
            f"{r.name:<30} {r.kind:<8} {r.learned.render():<33} "
            f"{r.learned_enforce.render():<33} {r.patterns.render():<33} {r.withheld.render()}"
        )


def by_source(name: str, examples: tuple[Example, ...]) -> dict[str, list[Example]]:
    out: dict[str, list[Example]] = {}
    for e in examples:
        out.setdefault(f"{name}/{e.source}", []).append(e)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--unseal", action="store_true", help="score the sealed sets, once")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)  # the firewall logs every screening
    model = load_model()
    existing = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    if args.unseal and existing.get("sealed"):
        msg = (
            f"the sealed sets were already scored, with model {existing['sealed_on'][:12]}; "
            "refusing a second look"
        )
        raise SystemExit(msg)

    data = assemble(unseal=args.unseal)
    rows: list[Row] = []
    for name, members in by_source("validation", data.validation).items():
        rows += compare(name, members, model)
    for name, members in data.report.items():
        rows += compare(name, members, model)
    show(rows)
    result: dict[str, object] = {
        "model": dict(model.meta),
        "threshold": model.threshold,
        "enforce_threshold": model.enforce_threshold,
        "open": as_json(rows),
        "sealed": existing.get("sealed", []),
        "sealed_on": existing.get("sealed_on"),
    }

    if args.unseal:
        sealed: list[Row] = []
        for name, members in data.sealed.items():
            sealed += compare(name, members, model)
        evasion_dir = Path(default_root()) / "external" / "evasion"
        by_transform: dict[str, list[Example]] = {}
        for d in load_bipia(evasion_dir):
            by_transform.setdefault(d.category, []).append(
                Example(d.id, d.text, 1, d.group, "evasion", d.planted)
            )
        for transform, members in sorted(by_transform.items()):
            sealed += compare(f"evasion_v1/{transform}", members, model)
        print("\nSEALED, scored once:")
        show(sealed)
        result["sealed"] = as_json(sealed)
        result["sealed_on"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(f"\nWrote {RESULTS.relative_to(default_root().parent)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
