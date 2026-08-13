#!/usr/bin/env python3
"""Add `make load` and `make load-long`. Asserted, idempotent.

`Makefile` is a drift file and is never shipped whole; the anchor is checked
before anything is written.

A new script rather than an edit to `patch_makefile_task55.py`, per the rule
that patch scripts decide they have already run by matching their own inserted
text — editing one in place would make it stop recognising a file it had
already patched and append the whole block twice.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

# The smoke target has anchored two previous patches and is still current.
ANCHOR = "smoke:  ## Assert the composed stack actually works\n"

TARGETS = """load:  ## Load-test the composed stack for 30s and report latency by outcome
\tuv run locust -f perf/locustfile.py --host http://127.0.0.1:8080 \\
\t\t--headless --users 20 --spawn-rate 10 --run-time 30s

load-long:  ## The same, for 5 minutes at 100 users — for profiling (task 61)
\tuv run locust -f perf/locustfile.py --host http://127.0.0.1:8080 \\
\t\t--headless --users 100 --spawn-rate 20 --run-time 5m

"""

# Not edited — asserted. Adding make targets that shell out to a file which is
# not there produces a confusing error two layers from the cause.
REQUIRED = ("perf/locustfile.py", "perf/scenarios.py")


def main() -> int:
    path = ROOT / MAKEFILE
    print(f"Adding load-test targets to {MAKEFILE}")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    for name in REQUIRED:
        if not (ROOT / name).exists():
            msg = (
                f"{name} is missing, so `make load` would fail with a locust "
                f"error rather than a useful one. NOTHING HAS BEEN WRITTEN."
            )
            raise SystemExit(msg)

    text = path.read_text(encoding="utf-8")

    if TARGETS in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{MAKEFILE} does not contain the `smoke:` target this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGETS + ANCHOR, 1), encoding="utf-8")
    print("  applied: make load / make load-long")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
