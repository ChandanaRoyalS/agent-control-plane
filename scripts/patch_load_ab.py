#!/usr/bin/env python3
"""Make `fsync` switchable from the shell, so ADR 0050 §8 can be measured.

Two drift files, `docker-compose.yml` and `Makefile`. **Every anchor is checked
before anything is written**, so a half-patched pair is not a state this can
produce.

**Why this exists.** ADR 0050 decision 8 declared the cost of `fsync` per audit
entry — "it bounds write throughput to the disk's sync rate" — and said Phase 8
would measure it. Task 60's first honest run made that urgent: 2.3x the offered
load bought 2.3x the throughput and **25x the p50 latency**, which is a queue
rather than a slowdown, and the audit sink is the only synchronous disk write
on the request path.

This does not answer the question. It makes the experiment one command:

    make load            # fsync on, the default
    make load-nofsync    # fsync off, same everything else

The difference between those two runs is the price of durability on this
machine's disk. If it is small, the queue is somewhere else and task 61 goes
looking with a profiler. If it is large, ADR 0050 §8 has its number and a real
deployment has a decision to make.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# --- docker-compose.yml -----------------------------------------------------

# Written by `patch_audit_wiring.py`, so its exact text is known.
COMPOSE_ANCHOR = '      ACP_AUDIT_REQUIRED: "true"\n'

COMPOSE_ENV = """      # Switchable, so ADR 0050 §8's declared cost can be measured rather than
      # asserted (task 60). `make load` runs with it on; `make load-nofsync`
      # runs the identical mix with it off, and the difference is what
      # durability costs on this machine's disk.
      #
      # Defaulted to true, so the honest setting is the one you get without
      # asking for it. A record buffered in the kernel when the machine loses
      # power describes a call that really happened, and that is precisely the
      # crash-adjacent window an investigation cares about.
      ACP_AUDIT_FSYNC: "${ACP_AUDIT_FSYNC:-true}"
"""

# --- Makefile ---------------------------------------------------------------

# Written by `patch_makefile_load.py`, so its exact text is known.
MAKE_ANCHOR = "load:  ## Load-test the composed stack for 30s and report latency by outcome\n"

MAKE_TARGET = """load-nofsync:  ## The same load test with the audit sink's fsync off (ADR 0050 §8)
\t@echo "Restarting the gateway with ACP_AUDIT_FSYNC=false ..."
\tACP_AUDIT_FSYNC=false docker compose up -d --wait gateway
\t-$(MAKE) load
\t@echo "Restoring the default (fsync on) ..."
\tdocker compose up -d --wait gateway

"""

EDITS = (
    ("docker-compose.yml", COMPOSE_ANCHOR, COMPOSE_ANCHOR + COMPOSE_ENV, "switchable fsync"),
    ("Makefile", MAKE_ANCHOR, MAKE_TARGET + MAKE_ANCHOR, "make load-nofsync"),
)


def main() -> int:
    print("Making the audit sink's fsync switchable, for the Phase 8 A/B.")

    # Every anchor checked before anything is written (rule 2d). A compose file
    # that reads ACP_AUDIT_FSYNC with no make target to set it is merely
    # useless; a make target that sets a variable compose ignores would report
    # a *measurement* that never changed the thing it claims to have changed.
    for name, anchor, replacement, label in EDITS:
        path = ROOT / name
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 1
        text = path.read_text(encoding="utf-8")
        if replacement not in text and anchor not in text:
            msg = (
                f"{name} does not contain the anchor for {label!r}, and does not "
                f"already have the change. NOTHING HAS BEEN WRITTEN. Check that "
                f"tasks 56-57 and 60 are applied."
            )
            raise SystemExit(msg)

    for name, anchor, replacement, label in EDITS:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        if replacement in text:
            print(f"  already applied: {label}")
            continue
        path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
        print(f"  applied: {label}")

    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
