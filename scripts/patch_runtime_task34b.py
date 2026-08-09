"""Load the policy at startup and thread it to build_app.

Asserted patch (rule 2): runtime.py is hand-edited and SDK-dependent. Four edits:
  1. import load_policy + Policy
  2. gateway_from_configs gains `policy: Policy | None = None`
  3. that policy is passed into build_app
  4. gateway_from_settings loads policy_file via load_policy and passes it down

The policy loads before any connection opens, beside load_upstreams, so a
malformed policy fails the boot with a named file (ADR 0025) rather than a
surprise on the first call.

    python3 scripts/patch_runtime_task34b.py
"""

from __future__ import annotations

import sys
from pathlib import Path

RUNTIME = Path("src/acp/runtime.py")


def main() -> int:
    if not RUNTIME.exists():
        print(f"{RUNTIME} not found — run from repo root", file=sys.stderr)
        return 1
    t = RUNTIME.read_text(encoding="utf-8")
    if "load_policy" in t:
        print("policy loading already wired into runtime.py — nothing to do")
        return 0

    edits: list[tuple[str, str]] = []

    # 1. imports
    _cfg_import = (
        "from acp.config import GatewaySettings, allowed_hosts_for, load_issuers, load_upstreams\n"
    )
    edits.append(
        (
            _cfg_import,
            _cfg_import
            + "from acp.policy import Policy\n"
            + "from acp.policy.loader import load_policy\n",
        )
    )

    # 2. gateway_from_configs signature — add policy after resource
    edits.append(
        (
            "    validator: TokenValidator | None = None,\n"
            "    resource: ProtectedResource | None = None,\n"
            "    credentials: ExchangedCredentials | None = None,\n"
            "    secrets: Mapping[str, str] | None = None,\n"
            ") -> AsyncIterator[Starlette]:",
            "    validator: TokenValidator | None = None,\n"
            "    resource: ProtectedResource | None = None,\n"
            "    credentials: ExchangedCredentials | None = None,\n"
            "    secrets: Mapping[str, str] | None = None,\n"
            "    policy: Policy | None = None,\n"
            ") -> AsyncIterator[Starlette]:",
        )
    )

    # 3. pass policy into build_app
    edits.append(
        (
            "            validator=validator,\n"
            "            resource=resource,\n"
            "        )\n"
            "        # Attached rather than yielded,",
            "            validator=validator,\n"
            "            resource=resource,\n"
            "            policy=policy,\n"
            "        )\n"
            "        # Attached rather than yielded,",
        )
    )

    # 4. gateway_from_settings loads the policy, beside load_upstreams,
    #    and passes it into gateway_from_configs.
    edits.append(
        (
            "    upstreams = load_upstreams(settings.upstreams_file)\n",
            "    upstreams = load_upstreams(settings.upstreams_file)\n"
            "    policy = load_policy(settings.policy_file)\n",
        )
    )
    edits.append(
        (
            "            credentials=ExchangedCredentials(exchanger) if exchanger else None,\n"
            "            secrets=secrets,\n"
            "        ) as app:",
            "            credentials=ExchangedCredentials(exchanger) if exchanger else None,\n"
            "            secrets=secrets,\n"
            "            policy=policy,\n"
            "        ) as app:",
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

    RUNTIME.write_text(t, encoding="utf-8")
    print("wired policy loading into runtime.py (5 edits)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
