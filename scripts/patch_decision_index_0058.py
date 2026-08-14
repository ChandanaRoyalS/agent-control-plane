#!/usr/bin/env python3
"""Add ADR 0058 to the decision index, and correct the count.

    python3 scripts/patch_decision_index_0058.py

Two anchors, and **both are checked before either is written** (rule 2d).

`tests/unit/docs/test_decision_index.py` fails if any ADR is unindexed, so this
is not optional politeness -- it is the reason task 66 built that test. The
count in the opening sentence is not tested and is corrected here anyway,
because a document that miscounts its own contents is the front-page problem
one directory down (lesson 67).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("docs/decisions/README.md")

MARKER = "0058-a-version-is-a-promise-about-a-surface.md"

ANCHOR_COUNT = "Fifty-seven decisions, each about ten minutes to read, each with the\n"
REPLACEMENT_COUNT = "Fifty-eight decisions, each about ten minutes to read, each with the\n"

ANCHOR_GROUP = (
    "| [0057](0057-the-demo-reports-what-happened-it-does-not-assert-it.md) | "
    "three temptations refused, and the finding that only a demo willing to be "
    "surprised could produce |\n"
)

ROW = (
    "| [0058](0058-a-version-is-a-promise-about-a-surface.md) | a version "
    "number is a promise about a surface, so the surface is a file and a test "
    "fails when it changes |\n"
)

GROUP = "\n## The release\n\n| | |\n|---|---|\n" + ROW


def main() -> int:
    path = ROOT / TARGET
    print("Adding ADR 0058 to the decision index.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if MARKER in text:
        print("  already applied")
        print("done.")
        return 0

    missing = [
        name
        for name, anchor in (
            ("the opening count sentence", ANCHOR_COUNT),
            ("the 0057 row", ANCHOR_GROUP),
        )
        if anchor not in text
    ]
    if missing:
        msg = (
            f"{TARGET} is missing {', '.join(missing)}, and does not already "
            f"have the change. NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    text = text.replace(ANCHOR_COUNT, REPLACEMENT_COUNT, 1)
    text = text.replace(ANCHOR_GROUP, ANCHOR_GROUP + GROUP, 1)
    path.write_text(text, encoding="utf-8")

    print("  applied: the count")
    print("  applied: a `The release` group with 0058")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
