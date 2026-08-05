"""Integration tests for the inbound gateway server.

Two in-process ASGI transports stacked: a client speaks HTTP to the gateway app,
and the gateway's ``UpstreamClient`` speaks HTTP to a mock upstream. No sockets,
no external processes — the same strategy as every other test here, applied to
the full request path for the first time.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.gateway import build_app
from acp.mocks import mock_a
from acp.mocks.chaos import CHAOS_MODE_HEADER
from acp.upstream import UpstreamClient, UpstreamConfig

pytestmark = pytest.mark.integration

# The streamable HTTP transport negotiates on Accept. Both types are sent
# because the server may answer either with JSON or with an SSE stream
# depending on the request; we ask for json_response=True but a client that
# only advertised JSON would be lying about what it can handle.
MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}


def gateway_client(*, chaos: str | None = None) -> tuple[Starlette, UpstreamClient]:
    """Build the gateway app wired to the mock upstream through ASGI."""
    upstream_headers = {CHAOS_MODE_HEADER: chaos} if chaos else {}
    upstream = UpstreamClient(
        UpstreamConfig(name="mock-a", url="http://mock/mcp"),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_a.app), headers=upstream_headers),
    )
    return build_app(upstream), upstream


def rpc(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return body


def call_gateway(body: dict[str, Any], *, chaos: str | None = None) -> dict[str, Any]:
    """POST one JSON-RPC request to the gateway and return the parsed response."""

    async def _run() -> dict[str, Any]:
        app, upstream = gateway_client(chaos=chaos)
        # ASGITransport speaks only the `http` scope — it never runs the ASGI
        # lifespan protocol. The SDK's streamable-HTTP app starts its session
        # manager's task group in lifespan, so without this the app serves
        # requests while uninitialised: "Task group is not initialized".
        async with upstream, app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            # The SDK validates the Host header as DNS-rebinding protection, and
            # `streamable_http_app` defaults to accepting 127.0.0.1. Using a
            # made-up hostname here would be testing against a security control
            # rather than through it.
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1"
            ) as client:
                response = await client.post("/mcp", json=body, headers=MCP_HEADERS)
                return _parse(response)

    return anyio.run(_run)


def _parse(response: httpx.Response) -> dict[str, Any]:
    """Read a JSON body, or the first data frame of an SSE stream."""
    text = response.text
    if text.lstrip().startswith("{"):
        parsed: dict[str, Any] = response.json()
        return parsed
    # SSE fallback: `event: message\ndata: {...}\n\n`
    for line in text.splitlines():
        if line.startswith("data:"):
            frame: dict[str, Any] = json.loads(line[len("data:") :].strip())
            return frame
    msg = f"could not parse gateway response: {text[:200]!r}"
    raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Passthrough
# ---------------------------------------------------------------------------


def test_gateway_serves_the_upstream_catalogue() -> None:
    """The whole point: a client asks the gateway and gets the upstream's tools."""
    body = call_gateway(rpc("tools/list"))

    names = [tool["name"] for tool in body["result"]["tools"]]
    assert names == ["read_document", "search", "create_ticket"]


def test_catalogue_preserves_the_wire_field_name_for_schema() -> None:
    """Through two conversions, `inputSchema` must survive as `inputSchema`.

    Our upstream model parses it, the SDK model re-serialises it. If either
    alias were wrong the tool would reach the agent with no schema — a silent
    failure a real client would experience as an unusable tool.
    """
    body = call_gateway(rpc("tools/list"))

    first = body["result"]["tools"][0]
    assert "inputSchema" in first
    assert first["inputSchema"]["type"] == "object"


def test_gateway_proxies_a_successful_tool_call() -> None:
    body = call_gateway(
        rpc("tools/call", {"name": "read_document", "arguments": {"path": "runbooks/deploy.md"}})
    )

    result = body["result"]
    assert "Deploy runbook" in result["content"][0]["text"]
    assert not result.get("isError", False)


def test_execution_failure_is_proxied_as_a_result_not_an_error() -> None:
    """The distinction has to survive the whole path, not just one layer.

    Upstream reports isError; the gateway must hand that to the agent as a
    result. Turning it into a protocol error would tell the agent the tool is
    broken when in fact its argument was wrong.
    """
    body = call_gateway(
        rpc("tools/call", {"name": "read_document", "arguments": {"path": "nope.md"}})
    )

    assert "error" not in body
    assert body["result"]["isError"] is True
    assert "no such document" in body["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# The taxonomy survives the boundary
# ---------------------------------------------------------------------------


def test_unreachable_upstream_becomes_a_protocol_error_with_recoverable_true() -> None:
    """A broken upstream must reach the agent as a structured, actionable error."""
    body = call_gateway(rpc("tools/list"), chaos="error")

    assert "error" in body
    assert body["error"]["data"]["recoverable"] is False
    assert body["error"]["data"]["upstream"] == "mock-a"


def test_malformed_upstream_response_is_not_recoverable() -> None:
    body = call_gateway(rpc("tools/list"), chaos="malformed")

    assert body["error"]["data"]["recoverable"] is False


def test_unknown_tool_is_rejected() -> None:
    body = call_gateway(rpc("tools/call", {"name": "no_such_tool", "arguments": {}}))

    assert "error" in body
    assert body["error"]["data"]["upstream_code"] == -32602
