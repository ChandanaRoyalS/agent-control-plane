#!/usr/bin/env python3
"""Add `make load-ab`: the A/B, repeated, so its numbers have a spread.

`Makefile` is a drift file; the anchor is checked before anything is written.
A new script rather than an edit to `patch_load_ab.py`, per the rule that a
patch script recognises "already applied" by its own inserted text.

**Why this exists.** The first A/B was one run per configuration, and the
numbers it produced disagreed with the next single run badly enough to look
like a regression. Three repetitions showed why: throughput rises monotonically
as the machine warms, so a single run understates and the first understates
most. The figure that looked like a regression — 41.9 req/s, measured straight
after a 40-second image build — sits *below* the range the same code produces
when measured three times.

It would have gone into an ADR as a fact.

So the repetition is a target rather than a habit somebody remembers:
alternating on/off, no rebuild in between, printing only the lines that matter.
**A number without a repetition count is a sample wearing a decimal point.**
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

# Written by `patch_load_ab.py`, so its exact text is known.
ANCHOR = "load-nofsync:  ## The same load test with the audit sink's fsync off (ADR 0050 §8)\n"

TARGET = """load-ab:  ## Three alternating fsync on/off runs, so the numbers carry a range
\t@echo "Six 30s runs, alternating. About five minutes. Do not use the machine."
\t@for rep in 1 2 3; do \\
\t\tfor sync in true false; do \\
\t\t\tACP_AUDIT_FSYNC=$$sync docker compose up -d --wait gateway >/dev/null 2>&1; \\
\t\t\techo "=== rep $$rep  fsync=$$sync ==="; \\
\t\t\tuv run locust -f perf/locustfile.py --host http://127.0.0.1:8080 \\
\t\t\t\t--headless --users 20 --spawn-rate 10 --run-time 30s 2>/dev/null \\
\t\t\t\t| grep -E '^  (throughput|served|listed|held) '; \\
\t\tdone; \\
\tdone
\t@echo "Restoring the default (fsync on) ..."
\t@docker compose up -d --wait gateway >/dev/null 2>&1

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make load-ab` — the A/B, repeated.")

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
            f"{MAKEFILE} does not contain the `load-nofsync` target this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN. Check that task 60's fix 2 is applied."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make load-ab")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
