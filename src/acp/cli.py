"""Command line entry point.

Subcommands land here as the phases do — ``probe`` and ``call`` in Phase 1,
``policy simulate`` in Phase 3, ``audit verify`` in Phase 7.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from acp import __version__


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser.

    Split out from ``main`` so tests can exercise parsing without a process exit.
    """
    parser = argparse.ArgumentParser(
        prog="acp",
        description="Agent Control Plane — a policy-enforcing MCP gateway.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_subparsers(dest="command", metavar="<command>")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    # No subcommands are implemented yet; Phase 1 adds `probe` and `call`.
    # Returning rather than calling `parser.error` (which is typed NoReturn)
    # keeps this function honestly typed as `-> int` and testable without
    # catching SystemExit.
    print(f"acp: unknown command: {args.command}", file=sys.stderr)  # noqa: T201
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
