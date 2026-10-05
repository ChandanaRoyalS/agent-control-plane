"""Command line entry point.

``probe`` and ``call`` exercise the outbound client against a real upstream; the
other commands serve the gateway or wrap the policy, schema, audit and secrets tools.
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
from acp.audit.checkpoint import DEFAULT_CHECKPOINT_PATH
from acp.audit.cli import (
    DEFAULT_PUBLIC_KEY_PATH,
    checkpoint_command,
    keygen_command,
    verify_command,
)
from acp.config import load_settings, load_upstreams
from acp.exceptions import ACPError
from acp.identity.principal import Actor, Principal
from acp.observability import configure_logging, configure_tracing
from acp.policy import Policy, evaluate
from acp.policy.loader import load_policy
from acp.policy.record import parse_traffic
from acp.policy.simulate import CHANGED, Outcome, simulate
from acp.runtime import gateway_from_settings
from acp.schema import SchemaSnapshot, diff
from acp.secrets import cli as secrets_cli
from acp.upstream import ListToolsResult, UpstreamClient, UpstreamConfig

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser; separate from ``main`` so tests avoid an exit."""
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
    _add_audit_commands(subparsers)
    _add_secrets_commands(subparsers)
    _add_policy_commands(subparsers)

    return parser


def _parse_args(pairs: list[str]) -> dict[str, str]:
    """Turn ``["k=v", ...]`` into a mapping, splitting on the first ``=``.

    Raises:
        ValueError: If a pair has no ``=`` or an empty key.
    """
    out: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            msg = f"--arg must be KEY=VALUE, got {pair!r}"
            raise ValueError(msg)
        out[key] = value
    return out


def _add_policy_commands(subparsers: Any) -> None:
    """``acp policy explain`` (one described request) and ``simulate`` (recorded traffic).

    Both use the gateway's own evaluator, never a copy of the rules (ADR 0030).
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
    explain.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="a call argument, repeatable; e.g. --arg doc_id=public",
    )

    simulate = actions.add_parser(
        "simulate",
        help="replay recorded decisions against a proposed policy and report what changes",
    )
    simulate.add_argument("--policy", required=True, help="path to the proposed policy file")
    simulate.add_argument(
        "--log",
        required=True,
        help="path to the gateway's decision log (JSON lines), or - for stdin",
    )
    simulate.add_argument(
        "--show",
        type=int,
        default=20,
        metavar="N",
        help="how many changed calls to print in full (default 20, 0 for all)",
    )


# Issuer for a described, never-authenticated principal.
SIMULATED_ISSUER = "urn:acp:simulator"


def _policy_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.policy_command not in ("explain", "simulate"):
        parser.parse_args(["policy", "--help"])
        return USAGE_ERROR

    try:
        policy = load_policy(Path(args.policy))
    except ACPError as exc:
        return _usage_error(f"could not load policy: {exc.message}")

    if args.policy_command == "simulate":
        return _simulate_command(policy, args)

    try:
        arguments = _parse_args(args.arg)
    except ValueError as exc:
        return _usage_error(str(exc))

    actor = Actor(subject=args.actor) if args.actor else None
    principal = Principal(subject=args.subject, issuer=SIMULATED_ISSUER, actor=actor)
    decision = evaluate(policy, principal, args.tool, arguments)

    verdict = "ALLOW" if decision.allowed else "DENY"
    print(f"{verdict}  {args.tool}")  # noqa: T201
    print(f"  subject: {args.subject}")  # noqa: T201
    if args.actor:
        print(f"  actor:   {args.actor}")  # noqa: T201
    for key, value in arguments.items():
        print(f"  arg:     {key}={value}")  # noqa: T201
    matched = decision.rule if decision.rule is not None else "(none - deny default)"
    print(f"  rule:    {matched}")  # noqa: T201
    print(f"  reason:  {decision.reason}")  # noqa: T201
    return 0 if decision.allowed else 1


CHANGES_FOUND = 1
"""Exit code when a simulated policy changes a decision; distinct from `USAGE_ERROR` for CI."""


def _read_log(path: str) -> list[str] | None:
    """The decision log's lines, or ``None`` after reporting why not."""
    if path == "-":
        return sys.stdin.readlines()
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _usage_error(f"could not read the decision log: {exc}")
        return None


def _simulate_command(policy: Policy, args: argparse.Namespace) -> int:
    """``acp policy simulate``: print counts, then up to ``--show`` changed calls."""
    lines = _read_log(args.log)
    if lines is None:
        return USAGE_ERROR

    traffic = parse_traffic(lines)
    if not traffic.decisions:
        print(f"No authorization decisions found in {args.log}.")  # noqa: T201
        print(  # noqa: T201
            f"  read {traffic.total} lines: {traffic.other_events} other events, "
            f"{traffic.unreadable} unreadable"
        )
        # Not a failure, but reported as "nothing measured", never "no changes".
        return 0

    simulation = simulate(policy, traffic)
    counts = simulation.counts

    print(  # noqa: T201
        f"Replayed {len(traffic.decisions):,} recorded decisions against {args.policy}"
    )
    if traffic.unreadable:
        print(f"  ({traffic.unreadable} lines could not be read and were skipped)")  # noqa: T201
    print()  # noqa: T201
    for outcome in Outcome:
        count = counts.get(outcome, 0)
        # Mark non-zero outcomes that are not proven safe.
        marker = "! " if count and outcome in CHANGED else "  "
        print(f"{marker}{count:>6,}  {outcome.value}")  # noqa: T201

    changed = simulation.changed
    if changed:
        shown = changed if args.show == 0 else changed[: args.show]
        print(f"\n{len(changed):,} call(s) not proven unchanged:")  # noqa: T201
        for replay in shown:
            print(f"\n  [{replay.outcome.value}] {replay.describe()}")  # noqa: T201
        if len(shown) < len(changed):
            print(f"\n  ... and {len(changed) - len(shown):,} more (--show 0 for all)")  # noqa: T201
        return CHANGES_FOUND

    print("\nNo call would be decided differently.")  # noqa: T201
    return 0


def _add_schemas_commands(subparsers: Any) -> None:
    """``acp schemas capture`` (a human acknowledges drift) and ``check`` (read-only)."""
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


def _add_audit_commands(subparsers: Any) -> None:
    """``acp audit verify | checkpoint | keygen``; wiring only, logic lives in ``acp.audit.cli``."""
    audit = subparsers.add_parser(
        "audit", help="verify the tamper-evident audit chain, and anchor it"
    )
    verbs = audit.add_subparsers(dest="audit_command", metavar="<verb>")

    for verb, help_text in (
        ("verify", "walk the chain and report any tampering; exit 1 on a break"),
        ("checkpoint", "record the current head as the anchor to verify against"),
    ):
        sub = verbs.add_parser(verb, help=help_text)
        sub.add_argument(
            "--log-file",
            type=Path,
            default=None,
            help="the audit chain (default: ACP_AUDIT_FILE)",
        )
        sub.add_argument(
            "--checkpoint",
            type=Path,
            default=DEFAULT_CHECKPOINT_PATH,
            help="the committed anchor (default: %(default)s)",
        )
        if verb == "verify":
            sub.add_argument(
                "--public-key",
                type=Path,
                action="append",
                default=None,
                help=(
                    "require every entry to be signed by this key; repeatable "
                    f"(default: {DEFAULT_PUBLIC_KEY_PATH}, if it exists)"
                ),
            )

    keygen = verbs.add_parser("keygen", help="make an Ed25519 key pair for signing entries")
    keygen.add_argument(
        "--private-key", type=Path, required=True, help="where to write the private key"
    )
    keygen.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY_PATH,
        help="where to write the public key (default: %(default)s)",
    )


def _audit_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    """Dispatch to ``acp.audit.cli``.

    ``--log-file`` beats ``ACP_AUDIT_FILE``; neither set is a usage error.
    """
    if args.audit_command is None:
        parser.parse_args(["audit", "--help"])
        return USAGE_ERROR  # pragma: no cover — argparse exits inside --help

    try:
        if args.audit_command == "keygen":
            return keygen_command(private_path=args.private_key, public_path=args.public_key)
        log_file = args.log_file or load_settings().audit_file
        if log_file is None:
            return _usage_error(
                "no audit log configured. Pass --log-file, or set ACP_AUDIT_FILE to "
                "the path this gateway writes its chain to."
            )
        if args.audit_command == "checkpoint":
            return checkpoint_command(log_file, checkpoint_path=args.checkpoint)
        keys = args.public_key
        if keys is None:
            keys = [DEFAULT_PUBLIC_KEY_PATH] if DEFAULT_PUBLIC_KEY_PATH.exists() else []
        return verify_command(log_file, checkpoint_path=args.checkpoint, public_keys=keys)
    except ACPError as exc:
        return _usage_error(exc.message)


def _add_secrets_commands(subparsers: Any) -> None:
    """``acp secrets init | set | list``; wiring only, logic lives in ``acp.secrets.cli``.

    There is deliberately no ``get``, so a credential is never printed to a terminal.
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

    # A table, so a new command is one line rather than another return branch.
    grouped = {
        "schemas": _schemas_command,
        "audit": _audit_command,
        "secrets": _secrets_command,
        "policy": _policy_command,
    }
    if args.command == "serve":
        return _serve_command(args)
    handler = grouped.get(args.command)
    if handler is not None:
        return handler(parser, args)
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
    """Run the gateway until interrupted; config is validated before any port is bound."""
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
    # After logging, so its decision is logged. Reads OTEL_* variables; a no-op
    # unless OTEL_TRACES_EXPORTER names an exporter.
    configure_tracing()

    # Lazy, so `acp probe` and `acp call` start fast.
    import uvicorn  # noqa: PLC0415

    def _server(app: Any, host: str, port: int) -> Any:
        return uvicorn.Server(
            uvicorn.Config(app, host=host, port=port, log_level=settings.log_level.lower())
        )

    async def run() -> int:
        async with gateway_from_settings(settings) as app:
            gateway = _server(app, settings.host, settings.port)

            if not settings.admin_enabled:
                # uvicorn drains on SIGTERM/SIGINT, then the context closes the pools.
                await gateway.serve()
                return 0

            monitor = getattr(app.state, "health", None)
            admin = _server(
                build_admin_app(
                    monitor,
                    getattr(app.state, "schema_drift", None),
                    # Must be the request path's own store, or approvals go nowhere.
                    getattr(app.state, "approvals", None),
                    settings.approval_operator_token,
                    getattr(app.state, "audit", None),
                    # Must be the hub the audit log publishes to, likewise.
                    console=getattr(app.state, "console", None),
                    operator_validator=getattr(app.state, "operator_validator", None),
                ),
                settings.admin_host,
                settings.admin_port,
            )
            logger.info(
                "admin.listening",
                extra={
                    "host": settings.admin_host,
                    "port": settings.admin_port,
                    # Logged because a missing channel is otherwise silent.
                    "approval_channel": bool(
                        (settings.approval_operator_token or settings.approval_operator_audience)
                        and getattr(app.state, "approvals", None) is not None
                    ),
                },
            )

            # Each server handles signals itself, so one SIGTERM drains both.
            async with anyio.create_task_group() as tg:
                tg.start_soon(admin.serve)
                if monitor is not None:
                    # Cancelled with the group when the gateway returns.
                    tg.start_soon(monitor.run)
                await gateway.serve()
                # Shutdown requested: stop admin too, or it holds the process open.
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
    """Read each upstream's catalogue sequentially, returning catalogues and failures.

    Uses a plain ``UpstreamClient``, not ``build_upstream``, so no cache is involved.
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
    """Record the current catalogues as the baseline.

    Refuses if any upstream failed, unless `allow_partial`, since a down upstream
    would be recorded as having no tools.
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
    """Compare live catalogues against the baseline, as a CI gate.

    Returns 1 on drift or on any unreachable upstream, which is never skipped.
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
    """Write guidance to stderr after flushing stdout, so piped output stays in order."""
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
    """Drive one coroutine; an ``ACPError`` prints its structured error and returns 1."""
    try:
        return int(asyncio.run(coro))
    except ACPError as exc:
        print(f"acp: {exc.message}", file=sys.stderr)  # noqa: T201
        print(json.dumps(exc.to_jsonrpc_error(), indent=2), file=sys.stderr)  # noqa: T201
        return FAILURE


async def _probe(config: UpstreamConfig) -> int:
    async with await UpstreamClient.connect(config) as client:
        catalogue = await client.list_tools()

    # Show cache hints too; `private` means the list was computed per caller.
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
        # A result, not a transport failure, but still a failing exit code.
        print(f"\nacp: {tool} reported isError", file=sys.stderr)  # noqa: T201
        return FAILURE
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
