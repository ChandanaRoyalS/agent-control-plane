#!/usr/bin/env python3
"""Add `make attack-demo`, and a way to run it with the firewall enforcing.

    python3 scripts/patch_makefile_attack.py

`Makefile` is a drift file, so this is an asserted patch.

**Two targets, because the interesting comparison is between them.** The
composed stack runs the firewall in `report` — where ADR 0038 says a deployment
starts — so `attack-demo` shows what happens when screening logs and changes
nothing: the poisoned document reaches the agent, and the *approval gate* is
what stops the exfiltration.

`attack-demo-enforce` restarts the gateway with `ACP_FIREWALL_MODE=enforce` and
runs the same script. If the document crosses the enforcement bar it is withheld
and the agent is never shown the instruction at all.

Neither target asserts which happens. The script reports, and the two runs
side by side are the argument — **defence in depth is only worth claiming if you
can show which layer caught it.**
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKEFILE = Path("Makefile")

ANCHOR = "smoke:  ## Assert the composed stack actually works\n"

TARGET = """attack-demo:  ## The same agent twice: direct, then through the gateway (task 64)
\tuv run python scripts/attack_demo.py

attack-demo-enforce:  ## The same demo with the firewall withholding, not just logging
\t@echo "Restarting the gateway with ACP_FIREWALL_MODE=enforce ..."
\t@ACP_FIREWALL_MODE=enforce docker compose up -d --wait gateway >/dev/null 2>&1
\t-uv run python scripts/attack_demo.py
\t@echo "Restoring the default (report) ..."
\t@docker compose up -d --wait gateway >/dev/null 2>&1

"""


def main() -> int:
    path = ROOT / MAKEFILE
    print("Adding `make attack-demo` and `make attack-demo-enforce`.")

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
            f"on, and does not already have the change. NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, TARGET + ANCHOR, 1), encoding="utf-8")
    print("  applied: make attack-demo, make attack-demo-enforce")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
