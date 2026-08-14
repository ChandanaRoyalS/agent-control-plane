#!/usr/bin/env python3
"""Bump `pyproject.toml` to 1.0.0.

    python3 scripts/patch_pyproject_version.py

`pyproject.toml` is on the drift list, so this is an asserted patch that
touches exactly one line.

The version lives in two files because packaging needs it here and the code
needs it importable, and `tests/unit/docs/test_release.py` asserts the two
agree. Single-sourcing through `importlib.metadata` was rejected in ADR 0058:
it reads the *installed* distribution, so a developer running from a checkout
gets whatever was last installed -- the same disagreement with a longer path to
noticing it.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("pyproject.toml")

ANCHOR = 'version = "0.1.0"\n'
REPLACEMENT = 'version = "1.0.0"\n'


def main() -> int:
    path = ROOT / TARGET
    print("Bumping pyproject.toml to 1.0.0.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if REPLACEMENT in text:
        print("  already applied")
        print("done.")
        return 0

    if text.count(ANCHOR) != 1:
        msg = (
            f"{TARGET} contains {text.count(ANCHOR)} lines reading "
            f'`version = "0.1.0"` (expected exactly 1), and does not already '
            f"have the change. NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print("  applied: 0.1.0 -> 1.0.0")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
