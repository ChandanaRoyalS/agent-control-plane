"""Add a `policy_file` field to GatewaySettings, after `upstreams_file`.

An asserted patch (standing rule 2): src/acp/config.py is hand-edited, so
shipping it whole would clobber drift. This asserts its anchor and aborts if the
surrounding lines have moved — a patch that aborts is the system working.

    python3 scripts/patch_settings_task32.py

Task 32 adds only the *setting*. The field is defined here and defaults to
config/policy.yaml, but nothing loads it yet — wiring load_policy() into startup
is task 33, alongside the evaluator that gives a loaded policy something to do.
Adding the field now keeps the config surface in one place and lets the ADR and
the committed policy.yaml reference a real setting.
"""

from __future__ import annotations

import sys
from pathlib import Path

CONFIG = Path("src/acp/config.py")

ANCHOR = (
    '    upstreams_file: Path = Path("config/upstreams.yaml")\n'
    '    """Path to the upstream definitions, resolved relative to the process\'s\n'
    '    working directory."""\n'
)

ADDITION = (
    "\n"
    '    policy_file: Path = Path("config/policy.yaml")\n'
    '    """Path to the policy rulebook (task 32), resolved relative to the\n'
    "    process's working directory.\n"
    "\n"
    "    Loaded and validated at startup in task 33; task 32 only defines the\n"
    "    setting and the schema it points at. A missing or malformed policy is a\n"
    "    boot failure, unlike the schema-baseline file above — policy is the\n"
    "    control, not a monitor of one, so its absence is fatal rather than\n"
    '    tolerated. See ADR 0025."""\n'
)


def main() -> int:
    if not CONFIG.exists():
        print(f"{CONFIG} not found — run from the repo root", file=sys.stderr)
        return 1

    text = CONFIG.read_text(encoding="utf-8")

    if "policy_file" in text:
        print("policy_file already present in GatewaySettings — nothing to do")
        return 0

    if ANCHOR not in text:
        print(
            "ABORT: the upstreams_file field was not found verbatim. It may have "
            "been edited; add policy_file by hand after it.",
            file=sys.stderr,
        )
        return 1

    text = text.replace(ANCHOR, ANCHOR + ADDITION, 1)
    CONFIG.write_text(text, encoding="utf-8")
    print("added policy_file to GatewaySettings, after upstreams_file")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
