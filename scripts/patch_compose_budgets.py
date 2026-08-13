#!/usr/bin/env python3
"""Turn the budget controls on in the composed stack, and choose their numbers.

    python3 scripts/patch_compose_budgets.py

`docker-compose.yml` is a drift file, so this is an asserted patch.

**The bug.** Task 62's configuration register printed this on its first run:

    [OFF] rate limit             a token-bucket draw per call
    [OFF] quota                  a windowed counter per principal
    [on ] cost-weighted budget   a per-tool weight on the budget draw

`ACP_COST_FILE` is set; `ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED` are
not, and both default to `False`. So `config/costs.yaml` is parsed at every
start and `gateway/server.py:_charge` opens with

    if payer is None or (limiter is None and quota is None):
        return

**A cost table read from disk to feed a decision nothing makes.** Tasks 39, 41
and 42 are built, tested, merged — and inert in the only deployment anybody
runs. Sixth instance of this failure, and the most complete: not a feature that
does nothing, but a file that is *read* for nothing.

**The numbers, and why they are not the defaults.**

The shipped defaults are a burst of 60 and a sustained 1 call/second
(`GatewaySettings`), which are sensible for a real deployment and would make
`make load` report ninety percent `THROTTLED` — a load test measuring the
limiter instead of the gateway. Raising them for the perf run and leaving the
demo at the defaults would be the same mistake in reverse: a number measured
under a configuration nobody deploys.

So the composed stack gets **numbers that bind for an abusive caller and not
for the load mix**:

- burst 500, sustained 200/s. One principal in `make load` offers about 28
  calls/second, so the limiter is live and never fires. An agent in a loop
  fires it immediately.
- 500,000 cost units per day. The load mix averages ~2.8 units per call
  (`config/costs.yaml` weights search 3 and summarise 10), so a 30-second run
  spends about 2,400 per principal — well inside a daily budget that still means
  something.

Every one is interpolated, so a demo can make them bind for one run:

    ACP_RATE_LIMIT_CAPACITY=5 ACP_RATE_LIMIT_REFILL_PER_SECOND=1 \\
        docker compose up -d --wait gateway

**What this changes about the numbers already published.** ADR 0054's overhead
figures were measured with both switched off, and its register says so on the
face of the run. Re-running `make overhead` after this will print `[on]` for
both and a slightly larger number — which is the register working, not a
regression.
"""

from __future__ import annotations

import sys
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

# Written by `patch_compose_firewall.py`, so its exact text is known.
ANCHOR = "      ACP_CACHE_FILE: /app/config/cache.yaml\n"

ADDITION = """      ACP_CACHE_FILE: /app/config/cache.yaml
      # -- and the controls that spend against that cost table ---------------
      #
      # Without these two, ACP_COST_FILE above is parsed at every start and
      # never read: `_charge` returns immediately when there is no limiter and
      # no quota. Tasks 39, 41 and 42, inert in the only deployment anybody
      # runs, until task 62's configuration register printed them as OFF.
      #
      # NOT the shipped defaults (burst 60, 1/second). Those are right for a
      # real deployment and would make `make load` report ninety percent
      # THROTTLED — a load test measuring the limiter rather than the gateway.
      # These bind for an abusive caller and not for the load mix: one
      # principal there offers about 28 calls/second.
      ACP_RATE_LIMIT_ENABLED: "${ACP_RATE_LIMIT_ENABLED:-true}"
      ACP_RATE_LIMIT_CAPACITY: "${ACP_RATE_LIMIT_CAPACITY:-500}"
      ACP_RATE_LIMIT_REFILL_PER_SECOND: "${ACP_RATE_LIMIT_REFILL_PER_SECOND:-200}"
      # In the same units the cost table weights, so a summarise costs ten of
      # these and a search three. The load mix averages ~2.8 per call.
      ACP_QUOTA_ENABLED: "${ACP_QUOTA_ENABLED:-true}"
      ACP_QUOTA_LIMIT: "${ACP_QUOTA_LIMIT:-500000}"
      # Interpolated so a demo can make either bind for one run:
      #   ACP_RATE_LIMIT_CAPACITY=5 ACP_RATE_LIMIT_REFILL_PER_SECOND=1 \\
      #       docker compose up -d --wait gateway
"""


def main() -> int:
    print("Wiring the budget controls into the composed stack.")

    if not COMPOSE.exists():
        print(f"missing: {COMPOSE}", file=sys.stderr)
        return 1

    text = COMPOSE.read_text(encoding="utf-8")

    if "ACP_RATE_LIMIT_ENABLED" in text:
        print("  already applied — docker-compose.yml already sets ACP_RATE_LIMIT_ENABLED")
        print("done.")
        return 0

    if text.count(ANCHOR) != 1:
        msg = (
            "docker-compose.yml does not contain exactly one\n"
            f"    {ANCHOR.strip()}\n"
            "line, and does not already have the change. NOTHING HAS BEEN "
            "WRITTEN. Check that scripts/patch_compose_firewall.py is applied."
        )
        raise SystemExit(msg)

    COMPOSE.write_text(text.replace(ANCHOR, ADDITION, 1), encoding="utf-8")
    print("  applied: rate limiting and quotas, with demo-scale numbers")
    print("verify with:  grep -E 'RATE_LIMIT|QUOTA' docker-compose.yml")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
