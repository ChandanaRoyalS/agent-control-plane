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
import logging
import sys
from collections.abc import Sequence
from typing import Any

import anyio

from acp import __version__
from acp.admin import build_admin_app
from acp.config import load_settings
from acp.exceptions import ACPError
from acp.observability import configure_logging, configure_tracing
from acp.runtime import gateway_from_settings
from acp.upstream import UpstreamClient, UpstreamConfig

logger = logging.getLogger(__name__)


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

    serve = subparsers.add_parser("serve", help="run the gateway")
    serve.add_argument("--host", help="override ACP_HOST")
    serve.add_argument("--port", type=int, help="override ACP_PORT")
    serve.add_argument("--upstreams-file", help="override ACP_UPSTREAMS_FILE")

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

    if args.command == "serve":
        return _serve_command(args)

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


def _serve_command(args: argparse.Namespace) -> int:
    """Run the gateway until interrupted.

    Configuration is read and validated before uvicorn is even imported, so a
    bad config fails in milliseconds with a readable message rather than after
    a port has been bound.
    """
    overrides = {
        key: value
        for key, value in (
            ("host", args.host),
            ("port", args.port),
            ("upstreams_file", args.upstreams_file),
        )
        if value is not None
    }

    try:
        settings = load_settings(**overrides)
    except ACPError as exc:
        return _usage_error(exc.message)

    configure_logging(settings.log_level, settings.log_format)
    # After logging, so the decision about whether tracing is on is itself
    # logged in the format the operator asked for. Reads OpenTelemetry's own
    # environment variables rather than ACP_ ones, and is a no-op unless
    # OTEL_TRACES_EXPORTER names an exporter.
    configure_tracing()

    # Imported here, not at module scope: `acp probe` and `acp call` are
    # diagnostic commands that must start instantly, and uvicorn pulls in a
    # noticeable amount of machinery only the server needs.
    import uvicorn  # noqa: PLC0415

    def _server(app: Any, host: str, port: int) -> Any:
        return uvicorn.Server(
            uvicorn.Config(app, host=host, port=port, log_level=settings.log_level.lower())
        )

    async def run() -> int:
        async with gateway_from_settings(settings) as app:
            gateway = _server(app, settings.host, settings.port)

            if not settings.admin_enabled:
                # uvicorn installs its own SIGTERM/SIGINT handling: it stops
                # accepting, drains in-flight requests, then returns — after
                # which the context manager closes the upstream pools. That
                # ordering is why the clients are managed around the server.
                await gateway.serve()
                return 0

            monitor = getattr(app.state, "health", None)
            admin = _server(build_admin_app(monitor), settings.admin_host, settings.admin_port)
            logger.info(
                "admin.listening",
                extra={"host": settings.admin_host, "port": settings.admin_port},
            )

            # Both servers in one task group. Each installs its own signal
            # handling, so a Ctrl+C or SIGTERM drains both and the group exits
            # when the last one returns — leaving the pools to close exactly as
            # they did with one server.
            async with anyio.create_task_group() as tg:
                tg.start_soon(admin.serve)
                if monitor is not None:
                    # Started here because this is where a task group legitimately
                    # lives. Cancelled with the group when the gateway returns.
                    tg.start_soon(monitor.run)
                await gateway.serve()
                # The gateway returning means shutdown was requested; the admin
                # listener has no reason to outlive it, and would hold the
                # process open if left running.
                admin.should_exit = True
                tg.cancel_scope.cancel()
        return 0

    return _run(run())


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
        catalogue = await client.list_tools()

    # The freshness hints are worth surfacing here: `acp probe` exists to show
    # what an upstream actually said, and whether it consents to being cached
    # is part of that. `private` means it computed this list for a particular
    # caller, which is the kind of thing you want to notice from a terminal
    # rather than from a cache that quietly declined to hold anything.
    print(f"{config.name}: {len(catalogue.tools)} tool(s)")  # noqa: T201
    print(  # noqa: T201
        f"  cache: ttlMs={catalogue.ttl_ms} scope={catalogue.cache_scope}"
        f" ({'shareable' if catalogue.is_shareable else 'not cached'})"
    )
    for tool in catalogue.tools:
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
