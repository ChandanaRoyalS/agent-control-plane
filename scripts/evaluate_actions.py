#!/usr/bin/env python3
"""What the policy engine does with the tool calls InjecAgent's attacks are after.

    uv run python scripts/evaluate_actions.py            # development half
    uv run python scripts/evaluate_actions.py --unseal   # ALSO held-out v2

The firewall reads text; this asks the other control. For every attacker
instruction in InjecAgent's development half, it takes the tool chain the attack
needs — `smartlock__GrantGuestAccess`, or `amazon__ViewSavedAddresses` then
`gmail__SendEmail` — and evaluates it against two policies built by rule (see
`acp.corpus.actions`). Deterministic and instant: no model, no network.
"""

from __future__ import annotations

import argparse

from acp.corpus.actions import READ_VERBS, ActionReport, evaluate_actions, load_actions
from acp.corpus.external import load_external_split

RULE = "=" * 78


def render(report: ActionReport, *, title: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}\n")
    print(f"  catalogue: {report.read_tools} read tools, {report.write_tools} write tools")
    print(f"  read verbs: {', '.join(READ_VERBS)}\n")
    print(f"  {'policy':<28} {'subset':<7} {'instr':>5}  blocked  held  executes")
    for row in report.rows:
        o = {k.value: v for k, v in row.outcomes.items()}
        print(
            f"  {row.policy:<28} {row.subset:<7} {row.instructions:>5}  "
            f"{o['blocked']:>7}  {o['held']:>4}  {o['executes']:>8}"
        )
        for group in row.executing:
            print(f"      executes: {group}")
    print("\n  THE COST — the users' own task tools under each policy")
    for b in report.burden:
        print(f"  {b.policy:<28} allowed {b.allowed}, held {b.held}, denied {b.denied}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--unseal", action="store_true", help="ALSO score held-out v2")
    args = parser.parse_args()
    split = load_external_split()
    actions = load_actions()
    render(
        evaluate_actions(actions, {d.group for d in split.development}),
        title="INJECAGENT ACTIONS — development half",
    )
    if args.unseal:
        if split.manifest.unsealed:
            print(
                f"\n  held-out v{split.manifest.version} was already unsealed "
                f"({split.manifest.unsealed}); the rows below are not unseen."
            )
        render(
            evaluate_actions(actions, {d.group for d in split.heldout}),
            title=f"INJECAGENT ACTIONS — HELD-OUT v{split.manifest.version}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
