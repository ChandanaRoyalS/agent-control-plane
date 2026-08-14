#!/usr/bin/env python3
"""Add the two ablation rungs the ladder never had: rate limit and quota.

    python3 scripts/patch_overhead_budget_rungs.py

`perf/overhead.py` is not on the drift list, but it is 600 lines and this
change is nine of them. An asserted patch that aborts on a moved anchor is
safer than reshipping a file from memory.

**Why they were missing.** The ladder was written during task 62, when
`ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED` were both unset — which is the
defect that run's register found (bug 81). You cannot ablate a control that is
already off: the rung would switch off something already off and measure
nothing, twice. Bug 81 turned them on, so now they can be.

**Appended, not inserted.** The ladder is cumulative: each rung inherits every
switch above it. Putting these at the bottom leaves every existing rung's
environment byte-identical, so the numbers already published from this ladder
still describe the configuration they claim to. Inserting in the middle would
silently invalidate every row below the insertion point — no error, a plausible
table, and the finding absent from the output. Lesson 46's shape exactly.

It also happens to be the right place on the stated ordering rule
(largest-expected-first): a token-bucket draw and a windowed counter are the two
cheapest things on the list.

**Both are predicted to land below the noise floor** and print as `·`. That
prediction is written into ADR 0054 before the run, because the interesting
outcome is the one that falsifies it: a budget control resolving *above* the
floor would mean it is doing IO, taking a lock, or otherwise serialising the
request path — none of which its design calls for, and all of which are
invisible to a functional test.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("perf/overhead.py")

# The final rung of the ladder, and the closing paren of the tuple. Anchoring on
# both together means a patch cannot append to some *other* tuple that happens
# to end the same way.
ANCHOR = """    Rung(
        label="- trace export",
        removes="a span per request, shipped over OTLP",
        switch={"OTEL_TRACES_EXPORTER": "none"},
    ),
)
"""

REPLACEMENT = """    Rung(
        label="- trace export",
        removes="a span per request, shipped over OTLP",
        switch={"OTEL_TRACES_EXPORTER": "none"},
    ),
    Rung(
        label="- quota",
        removes="a windowed counter read and incremented per call",
        switch={"ACP_QUOTA_ENABLED": "false"},
    ),
    Rung(
        label="- rate limit",
        removes="a token-bucket draw per call",
        switch={"ACP_RATE_LIMIT_ENABLED": "false"},
    ),
)
"""

MARKER = '"- rate limit"'


def main() -> int:
    path = ROOT / TARGET
    print("Adding the budget rungs to the ablation ladder.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if MARKER in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{TARGET} does not contain the trace-export rung this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print("  applied: - quota, - rate limit")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
