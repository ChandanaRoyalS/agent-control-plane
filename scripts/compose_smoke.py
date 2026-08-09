"""Prove the composed stack actually works, from outside every container.

Run against a stack brought up with `docker compose up -d --wait`:

    uv run python scripts/compose_smoke.py

This is what CI runs, and deliberately the same thing a human runs. A build
that produces an image nobody exercises is a build that reports success about a
tarball.

Six checks, and the last three are the ones worth having. Anyone can assert that
a container started. Asserting that a *real* MCP request crosses the gateway
into a containerised upstream and comes back with six qualified tools, that the
spans for it arrived in a separate container's trace backend, and that the same
request without a credential is refused, is asserting that the system is
assembled rather than merely running.

Since task 26 the composed gateway authenticates, so the request path here needs
a real token from the composed Keycloak. That is deliberate rather than
incidental: it means this file cannot pass against a stack whose authentication
is broken, which is the only way a smoke test stays honest as the system grows a
security boundary. The identity-specific assertions live in `identity_smoke.py`.

Written in Python rather than bash with `jq` because it has to parse JSON, an
SSE frame, and make assertions about both — and because the host is guaranteed
to have a Python that can do all three, where it is not guaranteed to have jq.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from keycloak_token import access_token

GATEWAY = os.environ.get("ACP_SMOKE_GATEWAY", "http://127.0.0.1:8080")
ADMIN = os.environ.get("ACP_SMOKE_ADMIN", "http://127.0.0.1:9090")
JAEGER = os.environ.get("ACP_SMOKE_JAEGER", "http://127.0.0.1:16686")

PROTOCOL_VERSION = "2026-07-28"
EXPECTED_TOOLS = 6
"""Three tools on each mock. A number, not a `> 0`, because "some tools came
back" would pass just as happily with one upstream silently missing."""

UNAUTHORIZED = 401

SERVER_ERROR = 500
"""Anything below this means something answered, which is all `wait_for` asks."""

failures: list[str] = []


def report(ok: bool, label: str, detail: str = "") -> None:
    print(f"{'  ok  ' if ok else ' FAIL '} {label}{f' — {detail}' if detail else ''}")
    if not ok:
        failures.append(label)


def get_json(url: str, timeout: float = 5.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 — fixed http URLs
        return json.loads(response.read())


def wait_for(url: str, *, seconds: float = 60.0) -> bool:
    """Poll until something answers.

    Present even though compose is started with `--wait`, because the two
    guarantee different things: `--wait` returns when Docker's healthchecks
    pass, and this returns when the thing is answering the request we are about
    to make. They are usually the same moment and occasionally are not.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                if response.status < SERVER_ERROR:
                    return True
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        time.sleep(1)
    return False


def mcp_request(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    token: str | None = None,
) -> dict[str, Any]:
    """One real MCP request, with the envelope a real server demands.

    The `_meta` keys and the `Mcp-Method` header are not optional decoration:
    the 2026-07-28 revision requires the envelope, and a server verifies the
    routing headers against the body (ADR 0008). A smoke test that skipped them
    would be testing a request shape no real client sends.
    """
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            **(params or {}),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "acp-smoke", "version": "0"},
            },
        },
    }
    request = urllib.request.Request(  # noqa: S310
        f"{GATEWAY}/mcp",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": method,
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
        return _decode(response.read().decode())


def refused_without_a_token() -> tuple[bool, str, str]:
    """The composed gateway sets ACP_AUTH_REQUIRED, so this must be a 401.

    Cheap, and it is the check that would catch the worst possible regression in
    this project: a gateway that starts believing it authenticates and serves
    anyway. Nothing else in this file would notice, because everything else
    sends a valid token.
    """
    try:
        mcp_request("tools/list")
    except urllib.error.HTTPError as exc:
        return exc.code == UNAUTHORIZED, "an unauthenticated request is refused", f"HTTP {exc.code}"
    return False, "an unauthenticated request is refused", "it was served"


def _decode(payload: str) -> dict[str, Any]:
    """Accept either a JSON body or an SSE frame.

    The SDK's streamable HTTP transport may answer either way depending on what
    it decides about the request, and a smoke test that only understood one of
    them would fail for a reason that has nothing to do with the gateway.
    """
    for line in payload.splitlines():
        if line.startswith("data:"):
            parsed: dict[str, Any] = json.loads(line[5:].strip())
            return parsed
    decoded: dict[str, Any] = json.loads(payload)
    return decoded


def main() -> int:
    print("waiting for the stack...")
    if not wait_for(f"{ADMIN}/healthz"):
        report(False, "gateway answers at all", f"{ADMIN}/healthz never responded")
        return 1

    # 1 — liveness
    report(wait_for(f"{ADMIN}/healthz", seconds=5), "liveness", f"{ADMIN}/healthz")

    # 2 — readiness, and every upstream reachable *by service name*
    ready = get_json(f"{ADMIN}/readyz")
    healthy = [u["upstream"] for u in ready["upstreams"] if u["state"] == "healthy"]
    report(
        ready["ready"] and sorted(healthy) == ["mock-a", "mock-b"],
        "both upstreams healthy over the compose network",
        f"ready={ready['ready']} healthy={sorted(healthy)}",
    )

    # 3 — the committed baseline holds inside a container too. Worth checking
    # separately: the baseline is keyed by upstream *name*, so if that keying
    # were ever accidentally URL-dependent, this is the only place it would show.
    schemas = get_json(f"{ADMIN}/schemas")
    report(
        schemas["baseline"] and not schemas["drift"],
        "schema baseline loaded and clean",
        f"baseline={schemas['baseline']} drift={schemas['drift']}",
    )

    # 4 — a real request, all the way through, with a real credential
    try:
        token = access_token("alice")
    except (RuntimeError, urllib.error.URLError, OSError) as exc:
        report(False, "obtained a token from Keycloak", str(exc))
        return 1

    result = mcp_request("tools/list", token=token).get("result", {})
    tools = [t["name"] for t in result.get("tools", [])]
    report(
        len(tools) == EXPECTED_TOOLS and all("__" in name for name in tools),
        f"tools/list returns {EXPECTED_TOOLS} qualified tools",
        f"{len(tools)}: {', '.join(sorted(tools))}",
    )

    # 5 — and the spans for it reached a different container
    report(*_traces_arrived())

    # 6 — and the same request without the credential does not work
    report(*refused_without_a_token())

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s) — {'; '.join(failures)}", file=sys.stderr)
        return 1
    print("all checks passed")
    return 0


def _traces_arrived() -> tuple[bool, str, str]:
    """Ask Jaeger whether it has heard of us.

    Export is asynchronous and batched, so this polls rather than asserting
    once. A failure here means the gateway produced spans nobody received,
    which looks identical to no instrumentation at all — the exact ambiguity
    the pinned image and the healthcheck exist to remove.
    """
    deadline = time.monotonic() + 30
    services: list[str] = []
    while time.monotonic() < deadline:
        try:
            services = get_json(f"{JAEGER}/api/services").get("data") or []
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            services = []
        if "agent-control-plane" in services:
            return True, "traces reached Jaeger", "agent-control-plane"
        time.sleep(2)
    return False, "traces reached Jaeger", f"services seen: {services}"


if __name__ == "__main__":
    raise SystemExit(main())
