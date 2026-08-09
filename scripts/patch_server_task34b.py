"""Wire policy enforcement into the gateway's on_call_tool handler.

Asserted patch (rule 2): server.py is hand-edited and SDK-dependent. Three edits:
  1. import current_principal + enforce_call + PolicyDeniedError
  2. add `policy: Policy | None = None` to build_server, and enforce in on_call_tool
  3. thread policy from build_app into build_server

Fail-closed: if a policy is loaded but the request has no principal, the call is
denied — a loaded policy means authorization is expected, and a missing principal
at that point is a misconfiguration that must not silently permit.

    python3 scripts/patch_server_task34b.py
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
    if "enforce_call" in t:
        print("policy enforcement already wired into server.py — nothing to do")
        return 0

    edits: list[tuple[str, str]] = []

    # --- edit 1: imports. Add after the registry import line. ---
    edits.append(
        (
            "from acp.gateway.registry import UpstreamRegistry\n",
            "from acp.gateway.registry import UpstreamRegistry\n"
            "from acp.identity.principal import current_principal\n"
            "from acp.policy import Policy, enforce_call\n"
            "from acp.exceptions import PolicyDeniedError\n",
        )
    )

    # --- edit 2: build_server signature gains policy ---
    edits.append(
        (
            "def build_server(registry: UpstreamRegistry) -> Server[None]:",
            "def build_server(\n"
            "    registry: UpstreamRegistry, *, policy: Policy | None = None\n"
            ") -> Server[None]:",
        )
    )

    # --- edit 3: enforce inside on_call_tool, before routing ---
    edits.append(
        (
            "    ) -> types.CallToolResult:\n"
            "        try:\n"
            "            result = await registry.call_tool(params.name, params.arguments or {})",
            "    ) -> types.CallToolResult:\n"
            "        if policy is not None:\n"
            "            # Fail-closed: a loaded policy means authorization is\n"
            "            # expected. A missing principal here is a misconfiguration\n"
            "            # (policy set, auth not), and must deny rather than permit.\n"
            "            principal = current_principal()\n"
            "            if principal is None:\n"
            "                raise to_mcp_error(\n"
            "                    PolicyDeniedError(\n"
            '                        f"call to {params.name!r} was not permitted",\n'
            '                        details={"rule": None, "tool": params.name},\n'
            "                    )\n"
            "                )\n"
            "            try:\n"
            "                enforce_call(policy, principal, params.name)\n"
            "            except ACPError as exc:\n"
            "                raise to_mcp_error(exc) from exc\n"
            "        try:\n"
            "            result = await registry.call_tool(params.name, params.arguments or {})",
        )
    )

    # --- edit 4: thread policy from build_app's build_server call ---
    edits.append(
        (
            "    app = build_server(registry).streamable_http_app(",
            "    app = build_server(registry, policy=policy).streamable_http_app(",
        )
    )

    # --- edit 5: build_app signature gains policy (keyword-only, defaults None) ---
    edits.append(
        (
            "    validator: TokenValidator | None = None,\n"
            "    resource: ProtectedResource | None = None,\n"
            ") -> Starlette:",
            "    validator: TokenValidator | None = None,\n"
            "    resource: ProtectedResource | None = None,\n"
            "    policy: Policy | None = None,\n"
            ") -> Starlette:",
        )
    )

    for old, new in edits:
        if old not in t:
            print(f"ABORT: anchor not found:\n{old[:80]!r}", file=sys.stderr)
            return 1
        if t.count(old) != 1:
            print(f"ABORT: anchor not unique ({t.count(old)}x):\n{old[:80]!r}", file=sys.stderr)
            return 1
        t = t.replace(old, new, 1)

    SERVER.write_text(t, encoding="utf-8")
    print("wired policy enforcement into server.py (5 edits)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
