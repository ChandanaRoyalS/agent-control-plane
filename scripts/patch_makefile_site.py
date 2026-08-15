#!/usr/bin/env python3
"""Add `make site` and `make site-check`.

    python3 scripts/patch_makefile_site.py

`Makefile` is a drift file, so this is an asserted patch. Its own `.PHONY` line
rather than an edit to the existing backslash-continued one, for the same reason
the release targets got theirs.

Two targets, not one with a flag: building the page and checking it is current
are different acts, and the second is what the test suite runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

ANCHOR = "smoke:  ## Assert the composed stack actually works\n"

TARGETS = """.PHONY: site site-check

site:  ## Generate docs/index.html from the captured demo and the audit chain
\tuv run python scripts/build_site.py
\t@echo
\t@echo "Open it:  file://$$(pwd)/docs/index.html"
\t@echo "Published at https://chandanaroyal719-bot.github.io/agent-control-plane/"
\t@echo "once Pages is set to deploy from main -> /docs."

site-check:  ## Fail if docs/index.html is out of date with its inputs
\tuv run python scripts/build_site.py --check

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding the site targets.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if "site-check:" in text:
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
    print("  applied: site, site-check")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
