#!/usr/bin/env python3
"""Point the composed stack at the config files it already mounts.

    python3 scripts/patch_compose_firewall.py

`docker-compose.yml` is on the drift list, so this is an asserted patch rather
than a whole file: it checks every anchor before writing anything, and stops
rather than half-editing a file that has moved.

**What was actually wrong.** Not the mount — `./config:/app/config:ro` has
carried the whole directory since task 21, so `costs.yaml` and `cache.yaml` have
been sitting inside the container all along. What was missing is anything
*pointing at them*. Four features built, tested, merged, and inert in the only
deployment anybody runs:

- ``ACP_COST_FILE`` — task 41's per-tool weighting. Without it every tool costs
  1.0, so the quota cannot tell a summarise from a search.
- ``ACP_CACHE_FILE`` — task 43's result cache. Without it nothing is cacheable,
  which is the same shape as not having built it.
- ``ACP_PROVENANCE_FRAMING_ENABLED`` — task 46's fence.
- ``ACP_FIREWALL_MODE`` — task 47's screening.

This is `gateway_from_settings` swallowing wiring for the fifth time, in the one
place a test cannot see it: the wiring is correct, and nothing sets the
variables.

**Why `report` and not `enforce`.** The composed stack is what somebody runs to
see the system work, and `report` is what ADR 0038 says a deployment starts on:
it screens everything, logs everything, and changes nothing a caller receives.
It is interpolated, so the attack demo can raise it for one run:

    ACP_FIREWALL_MODE=enforce docker compose up -d --wait gateway
"""

from __future__ import annotations

import sys
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

ANCHOR = """      ACP_SCHEMA_BASELINE_FILE: /app/config/schema-baseline.json
      ACP_HEALTH_PROBE_INTERVAL: "5.0"
"""

ADDITION = """      ACP_SCHEMA_BASELINE_FILE: /app/config/schema-baseline.json
      # -- budgets, caching and the firewall -------------------------------
      #
      # All four of these files were already mounted by `./config:/app/config:ro`
      # below. What was missing was anything pointing at them, so four merged
      # features did nothing in the only deployment anybody actually runs.
      ACP_COST_FILE: /app/config/costs.yaml
      ACP_CACHE_FILE: /app/config/cache.yaml
      # Two more content blocks than the upstream sent, which is a visible
      # change to the wire and therefore a deliberate one (ADR 0037). On here
      # because the firewall below is on: with framing enabled an unfenced block
      # is by construction the gateway speaking, which is what lets a refusal
      # notice be told apart from a document impersonating one.
      ACP_PROVENANCE_FRAMING_ENABLED: "true"
      # `report` screens every result, logs every finding, and changes nothing
      # the caller receives — where ADR 0038 says a deployment starts. It still
      # evaluates the enforcement bar and logs a result it *would* have withheld
      # as `would_refuse`, so the stack shows what enforcement would cost before
      # anybody pays it.
      #
      # Interpolated, so the attack demo can raise it for one run:
      #     ACP_FIREWALL_MODE=enforce docker compose up -d --wait gateway
      ACP_FIREWALL_MODE: "${ACP_FIREWALL_MODE:-report}"
      # Without this the exfiltration detector reports every image and can
      # withhold none of them, because it cannot tell a leak from a logo. Two
      # invented internal hosts: the mock fleet returns no URLs at all, so this
      # documents the shape rather than filtering anything today.
      ACP_FIREWALL_ALLOWED_HOSTS: '["docs.internal","cdn.internal"]'
      ACP_HEALTH_PROBE_INTERVAL: "5.0"
"""


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")

    if "ACP_FIREWALL_MODE" in text:
        print("already applied — docker-compose.yml already sets ACP_FIREWALL_MODE")
        return 0

    if text.count(ANCHOR) != 1:
        print(
            "docker-compose.yml has drifted: expected exactly one\n"
            "  ACP_SCHEMA_BASELINE_FILE / ACP_HEALTH_PROBE_INTERVAL pair.\n"
            "Refusing to guess. Add the ACP_COST_FILE, ACP_CACHE_FILE,\n"
            "ACP_PROVENANCE_FRAMING_ENABLED, ACP_FIREWALL_MODE and\n"
            "ACP_FIREWALL_ALLOWED_HOSTS entries to the gateway's environment by hand.",
            file=sys.stderr,
        )
        return 1

    COMPOSE.write_text(text.replace(ANCHOR, ADDITION), encoding="utf-8")
    print("docker-compose.yml: the gateway now reads costs, cache, framing and the firewall")
    print("verify with:  docker compose config | grep ACP_FIREWALL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
