#!/usr/bin/env python3
"""Correct the test count in the 1.0.0 changelog entry.

    python3 scripts/patch_changelog_test_count.py

The entry said **1839 tests**; the release ships **1893**. The changelog was
written a few commits before the release it describes, and the release added 54
tests to the very repository it was summarising. A small number, wrong on the
front page of the release.

**Editing a released section is normally the thing not to do**, and it is right
here for one reason: the published GitHub release body is generated from this
file, so the two can be brought back into agreement with

    make release-notes > /tmp/notes.md
    gh release edit v1.0.0 --notes-file /tmp/notes.md

which is the tooling working rather than a document being quietly rewritten.
The correction moves a number toward the truth rather than away from an
embarrassment; a *substantive* change to what 1.0.0 claimed would belong in
1.0.1's section instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("CHANGELOG.md")

ANCHOR = "- 1839 tests, 94% coverage, `mypy --strict` clean.\n"
REPLACEMENT = "- 1893 tests, 94% coverage, `mypy --strict` clean.\n"


def main() -> int:
    path = ROOT / TARGET
    print("Correcting the test count in the 1.0.0 entry.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if REPLACEMENT in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{TARGET} does not contain the test-count line this patch anchors "
            f"on, and does not already have the change. NOTHING HAS BEEN "
            f"WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print("  applied: 1839 -> 1893")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
