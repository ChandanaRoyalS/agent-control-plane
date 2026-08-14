#!/usr/bin/env python3
"""Print one release's notes from `CHANGELOG.md`.

    python scripts/release_notes.py                 # the current version
    python scripts/release_notes.py --version 1.0.0

Exits 1 if the changelog does not describe that version, which is what makes
the release workflow refuse to publish an undocumented release rather than
publishing an empty one.

The parsing is in `acp.changelog`, which is pure and tested. This is the file
that knows where the changelog lives and what to do when it is wrong.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from acp import __version__
from acp.changelog import notes

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print one release's notes.")
    parser.add_argument(
        "--version",
        default=__version__,
        help=f"which release (default: {__version__}, from acp.__version__)",
    )
    args = parser.parse_args(argv)

    if not CHANGELOG.exists():
        print(f"missing: {CHANGELOG}", file=sys.stderr)
        return 1

    body = notes(CHANGELOG.read_text(encoding="utf-8"), args.version)
    if body is None:
        print(
            f"CHANGELOG.md has no notes for {args.version}. "
            f"Add a '## [{args.version}] - YYYY-MM-DD' section before tagging.",
            file=sys.stderr,
        )
        return 1

    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
