"""Command line entry point.

``probe`` and ``call`` exist so you can point the gateway's outbound client at a
real upstream from a terminal and watch what it does. That matters more than it
sounds: a proxy you can only exercise through its own test suite is a proxy you
cannot debug when something odd happens against a real server.

Subcommands land here as the phases do — ``policy explain`` (task 36),
``audit verify`` in task 57.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import anyio

from acp import __version__
from acp.admin import build_admin_app
from acp.config import load_settings, load_upstreams
from acp.exceptions import ACPError
from acp.identity.principal import Actor, Principal
from acp.observability import configure_logging, configure_tracing
from acp.policy import evaluate
from acp.policy.loader import load_policy
from acp.runtime import gateway_from_settings
from acp.schema import SchemaSnapshot, diff
from acp.secrets import cli as secrets_cli
from acp.upstream import ListToolsResult, UpstreamClient, UpstreamConfig

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

    _add_schemas_commands(subparsers)
    _add_secrets_commands(subparsers)
    _add_policy_commands(subparsers)

    return parser


def _add_policy_commands(subparsers: Any) -> None:
    """``acp policy explain`` (task 36): the policy simulator.

    One evaluator, two paths. A live request reaches ``evaluate`` through the
    gateway; this reaches the same ``evaluate`` from a terminal, so the
    simulator and the gateway cannot disagree. No token, no upstream, no call.
    """
    policy = subparsers.add_parser("policy", help="inspect and simulate policy")
    actions = policy.add_subparsers(dest="policy_command", metavar="<action>")

    explain = actions.add_parser(
        "explain",
        help="show what the policy would decide for a synthetic request",
    )
    explain.add_argument("--policy", required=True, help="path to the policy file")
    explain.add_argument("--subject", required=True, help="the human subject")
    explain.add_argument("--actor", help="the acting agent's subject, if delegated")
    explain.add_argument("--tool", required=True, help="qualified tool name")


# The issuer on a simulated principal: never validated, never trusted. The
# simulator evaluates policy over an identity you describe; it does not
# authenticate one.
SIMULATED_ISSUER = "urn:acp:simulator"


def _policy_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.policy_command != "explain":
        parser.parse_args(["policy", "--help"])
        return USAGE_ERROR

    try:
        policy = load_policy(Path(args.policy))
    except ACPError as exc:
        return _usage_error(f"could not load policy: {exc.message}")

    actor = Actor(subject=args.actor) if args.actor else None
    principal = Principal(subject=args.subject, issuer=SIMULATED_ISSUER, actor=actor)
    decision = evaluate(policy, principal, args.tool)

    verdict = "ALLOW" if decision.allowed else "DENY"
    print(f"{verdict}  {args.tool}")  # noqa: T201
    print(f"  subject: {args.subject}")  # noqa: T201
    if args.actor:
        print(f"  actor:   {args.actor}")  # noqa: T201
    matched = decision.rule if decision.rule is not None else "(none - deny default)"
    print(f"  rule:    {matched}")  # noqa: T201
    print(f"  reason:  {decision.reason}")  # noqa: T201
    return 0 if decision.allowed else 1


def _add_schemas_commands(subparsers: Any) -> None:
    """``acp schemas capture`` and ``acp schemas check`` (task 20).

    Two verbs because the workflow has two halves and conflating them is the
    failure mode: a command that both reports drift *and* records it as the new
    normal can only ever tell you something once, and never tells the next
    person anything at all. ``capture`` is the act of acknowledgement, performed
    by a human and reviewed as a diff. ``check`` only ever reads.
    """
    schemas = subparsers.add_parser(
        "schemas", help="capture and check upstream tool schemas for drift"
    )
    verbs = schemas.add_subparsers(dest="schemas_command", metavar="<verb>")

    capture = verbs.add_parser("capture", help="record every catalogue as the new baseline")
    _add_baseline_arguments(capture)
    capture.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "capture even if an upstream is unreachable; its tools are dropped "
            "from the baseline, so use this only when you mean it"
        ),
    )

    check = verbs.add_parser("check", help="compare against the baseline; exit 1 on drift")
    _add_baseline_arguments(check)


def _add_secrets_commands(subparsers: Any) -> None:
    """``acp secrets init | set | list`` (task 29).

    Argparse wiring only. Every decision lives in ``acp.secrets.cli``, where a
    test can reach it — this module imports the MCP SDK, so anything written
    here is untestable and untype-checkable in the environment it is authored
    in, which is how three bugs have shipped so far.

    There is no ``get``. A command that prints a credential to a terminal is one
    that eventually prints it into a screen-share, a scrollback buffer or a
    support ticket, and the store exists so the value has one destination.
    """
    secrets = subparsers.add_parser(
        "secrets", help="manage the encrypted store for upstreams that cannot exchange"
    )
    verbs = secrets.add_subparsers(dest="secrets_command", metavar="<verb>")

    for verb, help_text in (
        ("init", "generate a key and an empty store"),
        ("set", "add or replace one secret, read from a prompt or stdin"),
        ("list", "show the names in the store, never the values"),
    ):
        sub = verbs.add_parser(verb, help=help_text)
        sub.add_argument(
            "--secrets-file",
            type=Path,
            default=Path("config/secrets.enc"),
            help="the encrypted store (default: %(default)s)",
        )
        sub.add_argument(
            "--key-file",
            type=Path,
            default=Path("config/secret.key"),
            help="the key that opens it (default: %(default)s)",
        )
        if verb == "set":
            sub.add_argument("name", help="the name an upstream's `credential_ref` points at")
        if verb == "init":
            sub.add_argument(
                "--force",
                action="store_true",
                help=(
                    "overwrite an existing key. Every secret in the current store "
                    "becomes permanently unreadable"
                ),
            )


def _secrets_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    """Dispatch to ``acp.secrets.cli``, turning its errors into exit codes."""
    verb = getattr(args, "secrets_command", None)
    if verb is None:
        parser.parse_args([args.command, "--help"])
        return USAGE_ERROR

    try:
        if verb == "init":
            secrets_cli.initialise(args.key_file, args.secrets_file, force=args.force)
            print(f"wrote {args.key_file} and {args.secrets_file}")  # noqa: T201
            print("keep the key out of git; `acp secrets set <name>` adds to the store")  # noqa: T201
            return 0

        if verb == "set":
            value = secrets_cli.read_value()
            held = secrets_cli.put(args.key_file, args.secrets_file, args.name, value)
            print(f"stored {args.name!r}; the store now holds: {', '.join(held)}")  # noqa: T201
            return 0

        if verb == "list":
            for name in secrets_cli.names(args.key_file, args.secrets_file):
                print(name)  # noqa: T201
            return 0
    except ACPError as exc:
        return _usage_error(exc.message)

    return _usage_error(f"unknown verb: {verb}")


def _add_baseline_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--upstreams-file", help="override ACP_UPSTREAMS_FILE")
    parser.add_argument("--baseline", help="override ACP_SCHEMA_BASELINE_FILE")


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

    if args.command == "schemas":
        return _schemas_command(parser, args)

    if args.command == "secrets":
        return _secrets_command(parser, args)

    if args.command == "policy":
        return _policy_command(parser, args)

    return _upstream_command(args)


def _upstream_command(args: argparse.Namespace) -> int:
    """``probe`` and ``call``: the two that point at one upstream directly."""
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
            admin = _server(
                build_admin_app(monitor, getattr(app.state, "schema_drift", None)),
                settings.admin_host,
                settings.admin_port,
            )
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


def _schemas_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    """Dispatch ``acp schemas <verb>``."""
    if args.schemas_command is None:
        parser.parse_args(["schemas", "--help"])
        return USAGE_ERROR  # pragma: no cover — argparse exits inside --help

    overrides = {"upstreams_file": args.upstreams_file} if args.upstreams_file else {}
    try:
        settings = load_settings(**overrides)
        upstreams = load_upstreams(settings.upstreams_file)
    except ACPError as exc:
        return _usage_error(exc.message)

    baseline_path = Path(args.baseline) if args.baseline else settings.schema_baseline_file

    if args.schemas_command == "capture":
        return _run(_capture(upstreams, baseline_path, allow_partial=args.allow_partial))
    return _check_command(upstreams, baseline_path)


def _check_command(upstreams: list[UpstreamConfig], baseline_path: Path) -> int:
    """Loaded before any network call, so a missing baseline costs no round trips."""
    try:
        baseline = SchemaSnapshot.load(baseline_path)
    except ACPError as exc:
        return _usage_error(exc.message)

    if baseline is None:
        return _usage_error(
            f"no schema baseline at {str(baseline_path)!r}; run `acp schemas capture` first"
        )
    return _run(_check(upstreams, baseline))


async def _fetch_catalogues(
    upstreams: Sequence[UpstreamConfig],
) -> tuple[dict[str, ListToolsResult], dict[str, str]]:
    """Read every configured upstream's catalogue, remembering what failed.

    A plain ``UpstreamClient`` rather than the assembled stack from
    ``build_upstream``: this must see what the server is saying *now*, and a
    cached catalogue (task 19) would let ``check`` certify a response from
    minutes ago as current.

    Sequential rather than concurrent, deliberately. This is a command a person
    runs at a terminal, where a readable failure that names one upstream beats
    shaving a few hundred milliseconds off a fan-out.
    """
    catalogues: dict[str, ListToolsResult] = {}
    failures: dict[str, str] = {}
    for config in upstreams:
        try:
            async with await UpstreamClient.connect(config) as client:
                catalogues[config.name] = await client.list_tools()
        except ACPError as exc:
            failures[config.name] = f"{type(exc).__name__}: {exc.message}"
    return catalogues, failures


async def _capture(upstreams: Sequence[UpstreamConfig], path: Path, *, allow_partial: bool) -> int:
    """Record the current catalogues as the acknowledged baseline.

    Refuses by default when any upstream failed, and that guard is the whole
    reason this is not a one-liner. Capturing while a server is down records it
    as having no tools, which turns a transient outage into a permanent, quietly
    committed deletion — and the next time it comes back, every tool it ever had
    is reported as newly added by an upstream nobody was suspicious of.
    """
    catalogues, failures = await _fetch_catalogues(upstreams)

    for name, error in sorted(failures.items()):
        print(f"  ! {name}: {error}", file=sys.stderr)  # noqa: T201
    if failures and not allow_partial:
        _advise(
            "acp: refusing to capture with upstreams unreachable — a baseline taken "
            "during an outage records their tools as deleted. Fix them, or pass "
            "--allow-partial if you mean it."
        )
        return FAILURE

    snapshot = SchemaSnapshot.from_catalogues(catalogues)
    changed = snapshot.save(path)
    total = sum(len(entry.tools) for entry in snapshot.upstreams.values())
    verb = "wrote" if changed else "unchanged"
    print(f"{verb} {path}: {len(snapshot.upstreams)} upstream(s), {total} tool(s)")  # noqa: T201
    return 0


async def _check(upstreams: Sequence[UpstreamConfig], baseline: SchemaSnapshot) -> int:
    """Compare live catalogues against the baseline. Exit 1 means drift.

    The exit code is the point: this is the shape of a CI gate. Run it against
    the mock fleet on every build and a change to what those servers expose
    cannot merge without somebody re-capturing the baseline in the same commit,
    which is exactly the review step the whole design is arranged around.

    An unreachable upstream fails the check rather than being skipped. "I could
    not tell" and "nothing changed" are different answers, and a checker that
    returns the second when it means the first is worse than no checker.
    """
    catalogues, failures = await _fetch_catalogues(upstreams)
    observed = SchemaSnapshot.from_catalogues(catalogues)
    report = diff(baseline, observed, known=[c.name for c in upstreams])

    for name, error in sorted(failures.items()):
        print(f"  ! {name} unreachable: {error}", file=sys.stderr)  # noqa: T201

    if not report.has_drift:
        print(f"no drift: {len(observed.upstreams)} upstream(s) match the baseline")  # noqa: T201
        return FAILURE if failures else 0

    print(f"drift detected: {report.outstanding} change(s)\n")  # noqa: T201
    for event in report.events:
        print(f"  {event.describe()}")  # noqa: T201
    _advise("review the change, then run `acp schemas capture` to acknowledge it.")
    return FAILURE


def _advise(message: str) -> None:
    """Write guidance to stderr, after everything already on stdout has landed.

    The flush is not decoration. Python block-buffers stdout when it is not a
    terminal and never buffers stderr, so `acp schemas check 2>&1 | tee` prints
    the advice *before* the drift it refers to — the two streams interleave by
    whichever happens to flush first. Any CLI that writes to both has this, and
    the fix is to make the boundary explicit rather than to hope. Found by
    capturing a demo to a file, which is the only way anyone ever finds it.
    """
    sys.stdout.flush()
    print(f"\n{message}", file=sys.stderr)  # noqa: T201


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
