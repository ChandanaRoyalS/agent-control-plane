"""One line in `tests/integration/test_runtime.py`, which the build sandbox has no copy of.

That file carries local edits and is never shipped whole — bug 26. So the change
arrives as an asserted patch instead: the anchor is checked before anything is
written, because an unasserted replace has destroyed two files in this project.

What changes and why: `auth_required` now defaults to True, so a settings object
that configures no identity provider is asserting something false. The test is
about unauthenticated mode, which is still supported — it just has to say so.

Idempotent. Run it twice and the second run tells you there was nothing to do.
"""

from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("tests/integration/test_runtime.py")

ANCHOR = '''def test_no_provider_configured_builds_no_validator() -> None:
    """`None` here is what makes the gateway run unauthenticated, which is how
    every task before this one behaved and has to keep working."""
    settings = GatewaySettings(_env_file=None)  # type: ignore[call-arg]'''

REPLACEMENT = '''def test_no_provider_configured_builds_no_validator() -> None:
    """`None` here is what makes the gateway run unauthenticated, which is how
    every task before this one behaved and has to keep working.

    `auth_required=False` since task 26. The default is now to refuse — a
    gateway that is a security control does not start without the thing that
    makes it one — so running unauthenticated is a thing a deployment asks for
    rather than a thing it drifts into.
    """
    settings = GatewaySettings(_env_file=None, auth_required=False)  # type: ignore[call-arg]'''


def main() -> int:
    if not PATH.exists():
        sys.exit(f"patch aborted: {PATH} not found — run this from the repository root")

    text = PATH.read_text(encoding="utf-8")

    if "auth_required=False" in text:
        print(f"{PATH} already patched; nothing to do.")
        return 0

    if ANCHOR not in text:
        sys.exit(
            f"patch aborted: could not find the anchor in {PATH}.\n"
            "Nothing was written. Make the change by hand instead: in\n"
            "`test_no_provider_configured_builds_no_validator`, change\n"
            "  GatewaySettings(_env_file=None)\n"
            "to\n"
            "  GatewaySettings(_env_file=None, auth_required=False)"
        )

    PATH.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print(f"{PATH} patched: unauthenticated mode is now asked for explicitly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
