"""Command line entry point.

``probe`` and ``call`` exist so you can point the gateway's outbound client at a
real upstream from a terminal and watch what it does. That matters more than it
sounds: a proxy you can only exercise through its own test suite is a proxy you
cannot debug when something odd happens against a real server.

Subcommands land here as the phases do — ``policy simulate`` in task 38,
``audit verify`` in task 57.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from typing import Any

from acp import __version__
from acp.exceptions import ACPError
from acp.upstream import UpstreamClient, UpstreamConfig


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser.

    Split out from ``main`` so tests can exercise parsing without a process exit.
    """
    parser = argparse.ArgumentParser(
        prog="acp",
        description="Agent Control Plane — a policy-enforcing MCP gateway.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    probe = subparsers.add_parser("probe", help="list the tools an upstream exposes")
    _add_upstream_arguments(probe)

    call = subparsers.add_parser("call", help="invoke one tool on an upstream")
    _add_upstream_arguments(call)
    call.add_argument("--tool", required=True, help="tool name")
    call.add_argument(
        "--args",
        default="{}",
        help='tool arguments as a JSON object, e.g. \'{"path": "runbooks/deploy.md"}\'',
    )

    return parser


def _add_upstream_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--url", required=True, help="upstream MCP endpoint URL")
    parser.add_argument(
        "--name",
        default="upstream",
        help="short identifier used in logs and errors (default: upstream)",
    )
    parser.add_argument("--connect-timeout", type=float, default=3.0, help="seconds (default: 3.0)")
    parser.add_argument("--read-timeout", type=float, default=30.0, help="seconds (default: 30.0)")


USAGE_ERROR = 2
"""Exit code for a user mistake: bad flags, bad config, unparseable arguments."""

FAILURE = 1
"""Exit code for a request that was well-formed but did not succeed."""


def _usage_error(message: str) -> int:
    """Report a user mistake on stderr and return the usage exit code."""
    print(f"acp: {message}", file=sys.stderr)  # noqa: T201
    return USAGE_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return USAGE_ERROR

    try:
        config = UpstreamConfig(
            name=args.name,
            url=args.url,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
        )
    except ValueError as exc:
        return _usage_error(f"invalid configuration: {exc}")

    if args.command == "probe":
        return _run(_probe(config))
    if args.command == "call":
        return _call_command(config, args)
    return _usage_error(f"unknown command: {args.command}")


def _call_command(config: UpstreamConfig, args: argparse.Namespace) -> int:
    """Parse and validate ``--args``, then invoke the tool."""
    try:
        arguments = json.loads(args.args)
    except json.JSONDecodeError as exc:
        return _usage_error(f"--args is not valid JSON: {exc}")
    if not isinstance(arguments, dict):
        return _usage_error("--args must be a JSON object")
    return _run(_call(config, args.tool, arguments))


def _run(coro: Any) -> int:
    """Drive one coroutine, turning taxonomy errors into a clean exit code.

    A stack trace is the wrong output for "the upstream is down" — that is an
    expected condition, and printing the structured error is more useful than
    dumping frames.
    """
    try:
        return int(asyncio.run(coro))
    except ACPError as exc:
        print(f"acp: {exc.message}", file=sys.stderr)  # noqa: T201
        print(json.dumps(exc.to_jsonrpc_error(), indent=2), file=sys.stderr)  # noqa: T201
        return FAILURE


async def _probe(config: UpstreamConfig) -> int:
    async with await UpstreamClient.connect(config) as client:
        tools = await client.list_tools()

    print(f"{config.name}: {len(tools)} tool(s)")  # noqa: T201
    for tool in tools:
        required = tool.input_schema.get("required", [])
        print(f"  {tool.name}({', '.join(required)})  {tool.description}")  # noqa: T201
    return 0


async def _call(config: UpstreamConfig, tool: str, arguments: dict[str, Any]) -> int:
    async with await UpstreamClient.connect(config) as client:
        result = await client.call_tool(tool, arguments)

    print(result.text())  # noqa: T201
    if result.is_error:
        # The tool ran and failed. That is a result, not a transport failure —
        # but the exit code should still reflect that it did not succeed.
        print(f"\nacp: {tool} reported isError", file=sys.stderr)  # noqa: T201
        return FAILURE
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
