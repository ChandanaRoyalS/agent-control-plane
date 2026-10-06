#!/usr/bin/env python3
"""Score the gateway's model (v1) and a candidate trained on data version 2, once (ADR 0079).

    uv run python scripts/train_classifier.py --data-version 2 --out /tmp/v2.json
    uv run python scripts/compare_learned.py --candidate /tmp/v2.json

Scores both models on the report-only sets and on AgentDojo's sealed half (a first look
for both), and the candidate on BIPIA test and evasion v1 (a third look; v1's numbers
there are in `corpus/learned/results.json`). Applies ADR 0079's rule, fixed before
training, and writes `corpus/learned/v2-comparison.json`. Refuses to run twice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Final

from acp.corpus.bipia import ATTACK, load_bipia
from acp.corpus.learned_eval import Row, as_json, score_sets, sealed_sets
from acp.corpus.loader import default_root
from acp.corpus.training import Example, assemble
from acp.firewall.learned import MODEL_PATH, LearnedModel, from_json

RECORD: Final = default_root() / "learned" / "v2-comparison.json"
V1_SEALED: Final = default_root() / "learned" / "results.json"


def load(path: Path) -> tuple[LearnedModel, str]:
    raw = path.read_bytes()
    return from_json(json.loads(raw)), hashlib.sha256(raw).hexdigest()


def hits(rows: list[Row], name: str, kind: str) -> tuple[int, int]:
    [row] = [r for r in rows if r.name == name and r.kind == kind]
    return row.learned_enforce.successes, row.learned_enforce.total


def v1_bipia_clean() -> tuple[int, int]:
    recorded = json.loads(V1_SEALED.read_text(encoding="utf-8"))
    [row] = [r for r in recorded["sealed"] if r["set"] == "bipia_test" and r["kind"] == "benign"]
    return row["learned_enforce"]["hits"], row["learned_enforce"]["total"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    if RECORD.exists():
        msg = f"{RECORD.name} exists: the sealed sets were already scored for this comparison"
        raise SystemExit(msg)
    logging.disable(logging.CRITICAL)  # the firewall logs every screening

    v1, v1_sha = load(MODEL_PATH)
    v2, v2_sha = load(args.candidate)
    if v2.meta.get("data_version") != 2:  # noqa: PLR2004
        msg = "the candidate was not trained on data version 2"
        raise SystemExit(msg)

    data = assemble(unseal=True, data_version=2)
    agentdojo_sets: dict[str, list[Example]] = {
        "agentdojo_test": list(data.sealed["agentdojo_test"])
    }
    for d in load_bipia(default_root() / "external" / "agentdojo"):
        if d.split == "test" and d.label == ATTACK:
            agentdojo_sets.setdefault(f"agentdojo_test/{d.category}", []).append(
                Example(d.id, d.text, 1, d.group, "agentdojo", d.planted)
            )
    third_look = {k: v for k, v in sealed_sets(data).items() if not k.startswith("agentdojo")}

    models: dict[str, dict[str, object]] = {
        "v1": {"sha256": v1_sha},
        "v2": {"sha256": v2_sha, "meta": dict(v2.meta)},
    }
    rows: dict[str, list[Row]] = {}
    for name, model in (("v1", v1), ("v2", v2)):
        report = score_sets(dict(data.report), model)
        first = score_sets(agentdojo_sets, model)
        rows[name] = report
        models[name].update(
            threshold=model.threshold,
            enforce_threshold=model.enforce_threshold,
            report_only=as_json(report),
            agentdojo_sealed=as_json(first),
        )
        show(f"{name}: report-only and AgentDojo sealed (first look)", report + first)
    third = score_sets(third_look, v2)
    models["v2"]["bipia_and_evasion_third_look"] = as_json(third)
    show("v2: BIPIA test and evasion v1 (third look)", third)
    record: dict[str, object] = dict(models)

    internal_attacks = [hits(rows[m], "internal_attacks", "attacks") for m in ("v1", "v2")]
    internal_benign = [hits(rows[m], "internal_benign", "benign") for m in ("v1", "v2")]
    bipia_clean_v1 = v1_bipia_clean()
    bipia_clean_v2 = hits(third, "bipia_test", "benign")
    rule = {
        "more_internal_attacks_caught": internal_attacks[1][0] > internal_attacks[0][0],
        "no_more_internal_benign_withheld": internal_benign[1][0] <= internal_benign[0][0],
        "no_more_bipia_clean_withheld": bipia_clean_v2[0] <= bipia_clean_v1[0],
    }
    record["rule"] = {
        **rule,
        "internal_attacks": internal_attacks,
        "internal_benign": internal_benign,
        "bipia_clean": [bipia_clean_v1, bipia_clean_v2],
        "replace": all(rule.values()),
    }
    RECORD.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"\nrule: {json.dumps(record['rule'])}")
    print(f"Wrote {RECORD.relative_to(default_root().parent)}", file=sys.stderr)
    return 0


def show(title: str, rows: list[Row]) -> None:
    print(f"\n{title}")
    for r in rows:
        enforce = r.learned_enforce.render()
        print(f"  {r.name:<40} {r.kind:<8} report {r.learned.render():<28} enforce {enforce}")


if __name__ == "__main__":
    raise SystemExit(main())
