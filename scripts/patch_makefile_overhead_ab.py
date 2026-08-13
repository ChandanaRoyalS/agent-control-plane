#!/usr/bin/env python3
"""Add `make overhead-ab`: attribute the fixed overhead instead of asserting it.

    python3 scripts/patch_makefile_overhead_ab.py

`Makefile` is a drift file, so this is an asserted patch. A new script rather
than an edit to `patch_makefile_overhead.py`, per the rule that a patch script
recognises "already applied" by its own inserted text.

**Why this exists.** The first `make overhead` run said the gateway adds 32.8 ms
at p50 to a cache-missing call and **16.0 ms to one served from memory**. The
second number is the interesting one: a cache hit touches no upstream and no
network, so 16 ms is the gateway's *own* fixed cost, and it is larger than the
entire thing the cache removes.

The obvious explanation is the audit `fsync` — task 61 already established it is
the most expensive single thing on the request path. **Obvious is not measured.**
ADR 0053's own methodological finding was that a plausible number taken once
went into a document as a fact and was wrong.

So this runs the same measurement across the two switches that could plausibly
own that 16 ms:

- `ACP_AUDIT_FSYNC` — the caller waiting for the disk, per audited call
- `ACP_HEALTH_PROBING_ENABLED` — the catalogue prober, which is not on the
  request path but shares the event loop with it every five seconds, and is
  therefore a candidate for the **tail** rather than the median

Four runs, `--brief`, each printing its own switch line — so the attribution and
the configuration it was measured under cannot be separated.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

# Written by `patch_makefile_overhead.py`, so its exact text is known.
ANCHOR = "overhead:  ## What the gateway adds versus calling the upstream directly (task 62)\n"

TARGET = """overhead-ab:  ## Attribute that overhead: fsync and the catalogue prober, on and off
\t@echo "Four runs, about five minutes. Do not use the machine."
\t@for sync in true false; do \\
\t\tfor probe in true false; do \\
\t\t\tACP_AUDIT_FSYNC=$$sync ACP_HEALTH_PROBING_ENABLED=$$probe \\
\t\t\t\tdocker compose up -d --wait gateway >/dev/null 2>&1; \\
\t\t\tuv run python scripts/measure_overhead.py --brief; \\
\t\tdone; \\
\tdone
\t@echo "Restoring the defaults (fsync on, probing on) ..."
\t@docker compose up -d --wait gateway >/dev/null 2>&1

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make overhead-ab` — attributing the fixed overhead.")

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
            f"{MAKEFILE} does not contain the `overhead` target this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN. Check that task 62's first archive is applied."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make overhead-ab")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
