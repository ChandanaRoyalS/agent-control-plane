#!/usr/bin/env python3
"""Compare the running code's public surface against the captured snapshot.

    python scripts/capture_surface.py            # compare; exit 1 on drift
    python scripts/capture_surface.py --capture  # accept the current surface

The same shape as `scripts/evaluate.py --capture`, and for the same reason: a
snapshot a person writes by hand is a wish, and a snapshot a machine writes is
a record. Accepting a change is deliberate, one command, and shows up in a pull
request as a diff somebody has to look at.

**That diff is the whole point.** Nothing here decides whether a change is
breaking; a person does, when they see `ACP_QUOTA_LIMIT` disappear from a
review. What the snapshot removes is the case where nobody sees it at all —
which is how a gateway ships a renamed environment variable, starts with the
old default, and reports nothing (lesson 46, six instances and counting).

This is the wiring; the decisions are in `acp.surface`, which is pure and
tested. This file exists because enumerating the CLI means importing the module
that builds it, and that module imports the MCP SDK.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from acp.cli import build_parser
from acp.surface import compare, describe, render

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs" / "surface.json"


def _load(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else None


def _write(path: Path, surface: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(surface, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--capture",
        action="store_true",
        help="accept the current surface as the snapshot",
    )
    args = parser.parse_args(argv)

    current = describe(build_parser())

    counts = (
        f"{len(current['settings'])} settings, "
        f"{len(current['commands'])} commands, "
        f"{len(current['audit']['fields'])} audit fields"
    )

    if args.capture:
        _write(SNAPSHOT, current)
        print(f"Captured the public surface: {counts}")
        print(f"  wrote {SNAPSHOT.relative_to(ROOT)}")
        print()
        print("Read the diff before committing it. A line leaving this file is")
        print("a promise leaving this release.")
        return 0

    captured = _load(SNAPSHOT)
    if captured is None:
        print(f"No snapshot at {SNAPSHOT.relative_to(ROOT)}.", file=sys.stderr)
        print("Run: make surface-capture", file=sys.stderr)
        return 2

    differences = compare(captured, current)
    print(f"The running code's surface: {counts}")
    print()
    print(render(differences))

    if not differences:
        return 0

    print()
    print("If this change is intended, accept it with:")
    print("    make surface-capture")
    print()
    print("and decide what it does to the version number (ADR 0058):")
    print("    a variable, command or audit field REMOVED or RENAMED -> major")
    print("    a default CHANGED                                     -> major")
    print("    anything ADDED                                        -> minor")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
