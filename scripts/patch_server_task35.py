"""Filter tools/list by policy in on_list_tools.

Asserted patch (rule 2): server.py is hand-edited and SDK-dependent. Two edits:
  1. import current_principal (if not already) + visible_tools
  2. filter the catalogue by policy in on_list_tools, fail-closed on no principal

Fail-closed matches on_call_tool (task 34b): a loaded policy with no principal
shows an empty catalogue rather than the full one — the same refusal, expressed
as invisibility.

    python3 scripts/patch_server_task35.py
"""

from __future__ import annotations

import sys
from pathlib import Path

SERVER = Path("src/acp/gateway/server.py")


def main() -> int:
    if not SERVER.exists():
        print(f"{SERVER} not found — run from repo root", file=sys.stderr)
        return 1
    t = SERVER.read_text(encoding="utf-8")
    if "visible_tools" in t:
        print("catalogue filtering already wired into server.py — nothing to do")
        return 0

    edits: list[tuple[str, str]] = []

    # 1. extend the policy import to include visible_tools.
    edits.append(
        (
            "from acp.policy import Policy, enforce_call\n",
            "from acp.policy import Policy, enforce_call, visible_tools\n",
        )
    )

    # 2. filter after the catalogue is fetched, before the failure checks that
    #    already operate on catalogue.tools. Filtering the ToolDefinition list in
    #    place on the Catalogue keeps every downstream use (failure logging,
    #    to_mcp_tool) unchanged.
    edits.append(
        (
            "        catalogue = await registry.list_tools()\n"
            "\n"
            "        if catalogue.is_total_failure:",
            "        catalogue = await registry.list_tools()\n"
            "\n"
            "        if policy is not None:\n"
            "            # Show only what this principal may call. Fail-closed, like\n"
            "            # on_call_tool: a loaded policy with no principal sees an\n"
            "            # empty catalogue, not the full one.\n"
            "            principal = current_principal()\n"
            "            visible = (\n"
            "                visible_tools(policy, principal, catalogue.tools)\n"
            "                if principal is not None\n"
            "                else []\n"
            "            )\n"
            "            catalogue = replace(catalogue, tools=visible)\n"
            "\n"
            "        if catalogue.is_total_failure:",
        )
    )

    for old, new in edits:
        if old not in t:
            print(f"ABORT: anchor not found:\n{old[:80]!r}", file=sys.stderr)
            return 1
        if t.count(old) != 1:
            print(f"ABORT: anchor not unique ({t.count(old)}x)", file=sys.stderr)
            return 1
        t = t.replace(old, new, 1)

    # ensure `replace` and `current_principal` are imported.
    if "from dataclasses import replace" not in t:
        t = t.replace(
            "from acp.policy import Policy, enforce_call, visible_tools\n",
            "from dataclasses import replace\n\n"
            "from acp.policy import Policy, enforce_call, visible_tools\n",
            1,
        )
    if "current_principal" not in t:
        t = t.replace(
            "from acp.policy import Policy, enforce_call, visible_tools\n",
            "from acp.identity.principal import current_principal\n"
            "from acp.policy import Policy, enforce_call, visible_tools\n",
            1,
        )

    SERVER.write_text(t, encoding="utf-8")
    print("wired catalogue filtering into server.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
