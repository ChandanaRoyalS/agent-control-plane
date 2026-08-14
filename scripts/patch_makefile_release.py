#!/usr/bin/env python3
"""Add `make surface`, `make surface-capture` and `make release-notes`.

    python3 scripts/patch_makefile_release.py

`Makefile` is a drift file, so this is an asserted patch.

Its own `.PHONY` line rather than an edit to the existing one: GNU make accepts
any number of `.PHONY` declarations, and appending to a backslash-continued
list four archives after it was written is a patch that has to guess where the
continuation ends.

`surface` and `surface-capture` are two targets rather than one with a flag,
because accepting a change to the published surface should be a different thing
to type than checking it. A flag on a target somebody runs by habit is a flag
somebody eventually adds to a habit.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

ANCHOR = "smoke:  ## Assert the composed stack actually works\n"

TARGETS = """.PHONY: surface surface-capture release-notes

surface:  ## Check the public surface still matches docs/surface.json (task 67)
\tuv run python scripts/capture_surface.py

surface-capture:  ## Accept the current public surface as the snapshot
\t@echo "Accepting the current surface. Read the diff before committing it:"
\t@echo "a line leaving docs/surface.json is a promise leaving this release."
\t@echo
\tuv run python scripts/capture_surface.py --capture

release-notes:  ## Print this version's section of CHANGELOG.md
\tuv run python scripts/release_notes.py

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding the release targets.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if "surface-capture:" in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{MAKEFILE} does not contain the `smoke` target this patch anchors "
            f"on, and does not already have the change. NOTHING HAS BEEN "
            f"WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGETS + ANCHOR, 1), encoding="utf-8")
    print("  applied: surface, surface-capture, release-notes")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
