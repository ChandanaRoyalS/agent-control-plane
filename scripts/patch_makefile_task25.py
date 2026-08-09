"""Add the `probe-cimd` target to the Makefile, beside `probe-resource`.

An asserted patch (standing rule 2): the Makefile is edited on Chandana's
machine, so shipping it whole would clobber drift. This asserts its anchors and
aborts if either is missing — a patch that aborts is the system working.

    python scripts/patch_makefile_task25.py
"""

from __future__ import annotations

import sys
from pathlib import Path

MAKEFILE = Path("Makefile")

# Anchor 1: the .PHONY line must list probe-resource, and must not already list
# probe-cimd. We add probe-cimd right after probe-resource on that line.
PHONY_OLD = "identity-smoke token idp-reset probe-resource prove-passthrough"
PHONY_NEW = "identity-smoke token idp-reset probe-resource probe-cimd prove-passthrough"

# Anchor 2: the probe-resource target block. We insert the new target after it.
RESOURCE_TARGET = (
    "probe-resource:  ## Measure what Keycloak does with RFC 8707's `resource`\n"
    "\tuv run python scripts/probe_resource_indicator.py\n"
)
CIMD_TARGET = (
    "\nprobe-cimd:  ## Measure whether Keycloak accepts a URL client_id (CIMD)\n"
    "\tuv run python scripts/probe_cimd.py\n"
)


def main() -> int:
    if not MAKEFILE.exists():
        print("Makefile not found — run from the repo root", file=sys.stderr)
        return 1

    text = MAKEFILE.read_text()

    if "probe-cimd" in text:
        print("probe-cimd already present in the Makefile — nothing to do")
        return 0

    if PHONY_OLD not in text:
        print(
            "ABORT: the expected .PHONY line was not found. It may have been "
            "edited. Expected to contain:\n  " + PHONY_OLD,
            file=sys.stderr,
        )
        return 1

    if RESOURCE_TARGET not in text:
        print(
            "ABORT: the probe-resource target block was not found verbatim. "
            "It may have been edited; add probe-cimd by hand.",
            file=sys.stderr,
        )
        return 1

    text = text.replace(PHONY_OLD, PHONY_NEW, 1)
    text = text.replace(RESOURCE_TARGET, RESOURCE_TARGET + CIMD_TARGET, 1)

    MAKEFILE.write_text(text)
    print("added probe-cimd to .PHONY and inserted its target after probe-resource")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
