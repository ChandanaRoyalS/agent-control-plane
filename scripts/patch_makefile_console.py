#!/usr/bin/env python3
"""Add `make console`: print where to watch and what to paste.

    python3 scripts/patch_makefile_console.py

`Makefile` is a drift file, so this is an asserted patch.

**Why a target that only prints.** The console needs two things a person has to
have to hand — a URL on the *admin* listener rather than the gateway's, and the
operator token — and the whole point of task 63 is a thing you can watch for
thirty seconds. A demo that starts with "now find the token in
docker-compose.yml" has already spent the thirty seconds.

It deliberately does not open a browser. `xdg-open` is absent on plenty of
systems, wrong under WSL, and a Makefile that tries to launch a GUI is a
Makefile that fails in CI for a reason nobody wants to debug.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

ANCHOR = "smoke:  ## Assert the composed stack actually works\n"

TARGET = """console:  ## Where to watch the live trace, and the token to paste (task 63)
\t@echo "Open      http://127.0.0.1:9090/console"
\t@token=$$(grep -E 'ACP_APPROVAL_OPERATOR_TOKEN' docker-compose.yml | sed 's/.*: *//'); \\
\t\techo "Paste     $${token:-<ACP_APPROVAL_OPERATOR_TOKEN is not set in docker-compose.yml>}"
\t@echo
\t@echo "The ADMIN listener, not the gateway's: the stream carries every"
\t@echo "principal's activity, so an agent must not be able to address it."
\t@echo "Drive some traffic with 'make smoke' and watch it arrive."

"""
# `sed`, not `grep -oP`: PCRE is a GNU extension and absent on BSD grep, and the
# first version of this line double-escaped its way to matching nothing at all.
# The `:-` default turns "the token is not configured" into a sentence rather
# than a blank space after the word Paste.


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make console` — where to watch, and what to paste.")

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
            f"{MAKEFILE} does not contain the `smoke` target this patch anchors "
            f"on, and does not already have the change. NOTHING HAS BEEN "
            f"WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make console")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
