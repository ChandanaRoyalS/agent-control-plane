#!/usr/bin/env python3
"""Publish the overhead as a multiple with a range, not a millisecond point.

    python3 scripts/patch_readme_overhead_range.py

`README.md` is the artifact a recruiter reads first, and lesson 67 is that the
front page is usually the stale thing. Two runs of `make overhead`, on two
afternoons, disagree by ~40% about the added milliseconds and by ~5% about the
ratio — so the ratio is what leaves this laptop intact and the milliseconds are
quoted with their spread rather than as a point.

An asserted patch rather than a reshipped README: it is 262 lines, Chandana owns
it now, and this is two of them.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("README.md")

LINK = "docs/decisions/0054-an-overhead-number-is-meaningless-without-its-switch-settings.md"

ANCHOR = (
    f"| gateway overhead, cache miss | **+32.8 ms** p50 | [ADR 0054]({LINK}) |\n"
    f"| gateway overhead, cache hit | +16.0 ms p50 | ADR 0054 |\n"
)

REPLACEMENT = (
    f"| gateway overhead, cache miss | **6.7-7.2x** a direct call "
    f"(+21 to +33 ms) p50 | [ADR 0054]({LINK}) |\n"
    f"| gateway overhead, cache hit | 3.2-3.4x (+9 to +16 ms) p50 | "
    f"ADR 0054 |\n"
)

MARKER = "6.7-7.2x"


def main() -> int:
    path = ROOT / TARGET
    print("Republishing the overhead as a multiple with a range.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if MARKER in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{TARGET} does not contain the two overhead rows this patch "
            f"anchors on, and does not already have the change. NOTHING HAS "
            f"BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print("  applied: 2 rows")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
