#!/usr/bin/env python3
"""Record the second overhead run in `perf/README.md`, beside the first.

    python3 scripts/patch_perf_readme_second_run.py

The first run is not deleted. It states its own premise — rate limiting and
quotas off — which is the register doing its job, and the more useful finding
only exists because there are two runs to hold against each other.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("perf/README.md")

ANCHOR = """**The cache is worth 15.3 ms** — the difference between the two gateway figures,
and the only claim either row supports on its own.
"""

ADDITION = """
#### Measured again, with the budget controls on

Bug 81 turned `ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED` on. The same
command, on the merged stack, on a later day:

| row | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|
| cache miss | 3.6 ms | 24.4 ms | **+20.7 ms** | +34.7 ms | +42.6 ms |
| cache hit | 4.3 ms | 13.7 ms | **+9.4 ms** | +20.8 ms | +23.7 ms |

**Two controls were added and every number went down.** That is impossible as a
statement about the code — a token-bucket draw and a windowed counter cannot
remove work — and unremarkable as a statement about the machine.

Which makes it a measurement rather than a mystery. The gateway's cache-miss
median fell 13.7 ms while its workload strictly grew, so between-session
variation on this harness is **at least 13.7 ms at p50 — 42% of the headline in
the table above.**

The control says the same thing. The direct call does identical work against the
same mock in both runs and moved from 5.3 → 3.6 ms and 6.8 → 4.3 ms. A machine
that is a third faster is a third faster for both paths, so its variation mostly
**divides out of a ratio and does not divide out of a difference**:

| | first run | second run | disagreement |
|---|---|---|---|
| cache miss, added p50 | +32.8 ms | +20.7 ms | **37%** |
| cache miss, gateway ÷ direct | 7.19x | 6.72x | **6%** |
| cache hit, added p50 | +16.0 ms | +9.4 ms | **41%** |
| cache hit, gateway ÷ direct | 3.35x | 3.19x | **5%** |

**Read the multiple; quote the milliseconds with their range.** Three
alternating rounds bound the variation within a session, which is what this
harness does and what ADR 0053 taught it to do. Nothing bounded the variation
*between* sessions until there were two to compare. See ADR 0054's amendment.

The cache is worth 10.7 ms in this run against 15.3 ms in the first — the same
spread, on a quantity that is a difference of two medians and therefore inherits
the noise of both.
"""

MARKER = "#### Measured again, with the budget controls on"


def main() -> int:
    path = ROOT / TARGET
    print("Recording the second overhead run in perf/README.md.")

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
            f"{TARGET} does not contain the 'cache is worth 15.3 ms' paragraph "
            f"this patch anchors on, and does not already have the change. "
            f"NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, ANCHOR + ADDITION, 1), encoding="utf-8")
    print("  applied: the second run")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
