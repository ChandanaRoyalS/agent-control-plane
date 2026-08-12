#!/usr/bin/env python3
"""Give the composed stack an approval channel. Asserted, idempotent.

`docker-compose.yml` is never shipped whole — it drifts. The edit asserts its
anchor first and aborts on the whole change if it is missing, because a patch
that half-applied would be worse than one that refused.

What it adds is three environment variables, and only one of them is
load-bearing: `ACP_APPROVAL_OPERATOR_TOKEN`. Without it the gateway still holds
the calls `policy.compose.yaml` gates, and nothing can ever answer them — a
deployment that is perfectly correct and completely useless, which is exactly
the case `build_approval_store` warns about at startup.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ANCHOR = "      ACP_SCHEMA_BASELINE_FILE: /app/config/schema-baseline.json\n"

ADDITION = """      # -- human-in-the-loop approvals (task 55) ---------------------------
      #
      # `policy.compose.yaml` holds `mock-a__create-ticket` for a person. This
      # is what makes answering possible: with no operator credential the
      # approval routes are not mounted at all, so every gated call would wait
      # out its TTL and be refused. The gateway says so at startup
      # (`approval.no_operator_channel`) rather than failing silently.
      #
      # The channel lives on the ADMIN listener (`:9090`), never on the MCP one
      # (`:8080`). That is the control, not the plumbing: an agent cannot
      # approve its own call because it cannot address the thing that approves
      # calls. See ADR 0049.
      #
      # Committed in the clear for the same reason the Keycloak client secret
      # above is: this stack is a demonstration on loopback. A real deployment
      # puts this in the secret store like any other production credential —
      # it is the one write on a listener that is otherwise read-only.
      ACP_APPROVAL_OPERATOR_TOKEN: dev-only-operator-token
      # Five minutes is the default. Named here because it is the default-deny
      # (ADR 0048) wearing the clothes of a timeout: raising it widens the
      # window in which one person's yes can still be spent.
      ACP_APPROVAL_TTL_SECONDS: "300"
      ACP_APPROVAL_MAX_PENDING: "256"
"""


def edit(path: Path, anchor: str, replacement: str, *, label: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if replacement in text:
        print(f"  already applied: {label}")
        return False
    if anchor not in text:
        msg = (
            f"{path.name} does not contain the anchor for {label!r}. Nothing has "
            f"been written. Check that this branch is at task 54."
        )
        raise SystemExit(msg)
    path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    print(f"  applied: {label}")
    return True


def main() -> int:
    compose = ROOT / "docker-compose.yml"
    if not compose.exists():
        print(f"missing: {compose}", file=sys.stderr)
        return 1

    print("Patching docker-compose.yml for task 55.")
    edit(compose, ANCHOR, ANCHOR + ADDITION, label="approval channel settings")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
