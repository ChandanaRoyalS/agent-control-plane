#!/usr/bin/env python3
"""Add `make overhead-ablate-repeat`: the ladder, three times.

    python3 scripts/patch_makefile_ablate_repeat.py

`Makefile` is a drift file, so this is an asserted patch. A new script rather
than an edit to `patch_makefile_ablate.py`, per the rule that a patch script
recognises "already applied" by its own inserted text.

**Why a second target rather than three passes by default.** One pass is eight
minutes and already prints the resolution floor, because the control is measured
once per configuration. Three passes is twenty-five minutes and buys tighter
estimates and a wider sample for the floor. Making the slow one the default
would mean the fast one never gets run; making it unavailable would mean the
question "is that step real?" has no better answer than the first one.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

# Written by `patch_makefile_ablate.py`, so its exact text is known.
ANCHOR = "overhead-ablate:  ## Itemise that overhead: remove one thing at a time, and total it\n"

TARGET = """overhead-ablate-repeat:  ## The same ladder three times, for a tighter resolution floor
\t@echo "Eighteen runs, about twenty-five minutes. Do not use the machine."
\tuv run python scripts/ablate_overhead.py --repeat 3

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make overhead-ablate-repeat` — the ladder, three times.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if TARGET in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{MAKEFILE} does not contain the `overhead-ablate` target this "
            f"patch anchors on, and does not already have the change. NOTHING "
            f"HAS BEEN WRITTEN. Check that acp-62-fix2 is applied."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make overhead-ablate-repeat")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
