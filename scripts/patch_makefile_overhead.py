#!/usr/bin/env python3
"""Add `make overhead`: what the gateway costs against a direct upstream call.

    python3 scripts/patch_makefile_overhead.py

`Makefile` is a drift file, so this is an asserted patch: the anchor is checked
before anything is written, and a moved anchor stops the script rather than
producing a half-edited Makefile.

A new script rather than an edit to `patch_makefile_ab.py`, per the rule that a
patch script recognises "already applied" by its own inserted text — sharing one
script between two insertions gives it two answers to that question.

**Why it is not folded into `make load`.** They measure different things and
mixing them would corrupt both. `load` runs 20 concurrent users and reports a
p50 dominated by queueing; `overhead` runs one request at a time so that
*nothing* is queueing, because the queue is exactly what has to be absent for a
difference to be attributable to the gateway. Running them together would put
the overhead measurement behind the load generator's own traffic.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

# Written by `patch_makefile_ab.py`, so its exact text is known.
ANCHOR = "load-ab:  ## Three alternating fsync on/off runs, so the numbers carry a range\n"

TARGET = """overhead:  ## What the gateway adds versus calling the upstream directly (task 62)
\t@echo "Sequential, one request in flight. About a minute. Do not use the machine."
\tuv run python scripts/measure_overhead.py

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make overhead` — the gateway's cost, against a direct call.")

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
            f"{MAKEFILE} does not contain the `load-ab` target this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN. Check that task 61's Makefile patch is applied."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make overhead")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
