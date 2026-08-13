#!/usr/bin/env python3
"""Add `make overhead-ablate`: the fixed cost, itemised.

    python3 scripts/patch_makefile_ablate.py

`Makefile` is a drift file, so this is an asserted patch. A new script rather
than an edit to `patch_makefile_overhead_ab.py`, per the rule that a patch
script recognises "already applied" by its own inserted text.

**Why this replaces the hand-rolled A/B loop rather than extending it.**
`overhead-ab` is a shell `for` loop over two switches; six switches would be a
nested loop nobody can read, printing six blocks somebody has to subtract in
their head. `scripts/ablate_overhead.py` walks the ladder in
`perf.overhead.ABLATION`, computes the marginal cost of each rung, and prints
one table.

`overhead-ab` stays, because a 2x2 is the right shape for asking whether one
switch owns the median or the tail, and the ladder is the right shape for asking
where all of it went.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

# Written by `patch_makefile_overhead_ab.py`, so its exact text is known.
ANCHOR = "overhead-ab:  ## Attribute that overhead: fsync and the catalogue prober, on and off\n"

TARGET = """overhead-ablate:  ## Itemise that overhead: remove one thing at a time, and total it
\t@echo "Six configurations, about eight minutes. Do not use the machine."
\tuv run python scripts/ablate_overhead.py

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make overhead-ablate` — the fixed cost, itemised.")

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
            f"{MAKEFILE} does not contain the `overhead-ab` target this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN. Check that the task 62 fix archive is applied."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make overhead-ablate")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
