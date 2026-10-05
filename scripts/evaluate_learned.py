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

from acp.corpus.learned_eval import Row, as_json, open_sets, score_sets, sealed_sets
from acp.corpus.loader import default_root
from acp.corpus.training import assemble
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
    rows = score_sets(open_sets(data), model)
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
        sealed = score_sets(sealed_sets(data), model)
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
