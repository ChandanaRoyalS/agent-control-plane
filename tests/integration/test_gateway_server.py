"""Integration tests for the inbound gateway server.

Two in-process ASGI transports stacked: a client speaks HTTP to the gateway app,
and each ``UpstreamClient`` speaks HTTP to a mock upstream. No sockets, no
external processes — the full request path, end to end.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.gateway import UpstreamRegistry, build_app
from acp.mocks import mock_a, mock_b
from acp.mocks.chaos import CHAOS_MODE_HEADER
from acp.upstream import UpstreamClient, UpstreamConfig

pytestmark = pytest.mark.integration

# The streamable HTTP transport negotiates on Accept. Both types are sent
# because the server may answer either with JSON or with an SSE stream; we ask
# for json_response=True, but a client advertising only JSON would be
# misrepresenting what it can handle.
MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}


def _client(app: Any, name: str, chaos: str | None) -> UpstreamClient:
    headers = {CHAOS_MODE_HEADER: chaos} if chaos else {}
    return UpstreamClient(
        UpstreamConfig(name=name, url="http://mock/mcp"),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), headers=headers),
    )


def gateway(
    *, a_chaos: str | None = None, b_chaos: str | None = None
) -> tuple[Starlette, list[UpstreamClient]]:
    """The gateway app wired to both mock upstreams through ASGI."""
    clients = [
        _client(mock_a.app, "mock-a", a_chaos),
        _client(mock_b.app, "mock-b", b_chaos),
    ]
    return build_app(UpstreamRegistry(clients)), clients


def rpc(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return body


def call_gateway(
    body: dict[str, Any], *, a_chaos: str | None = None, b_chaos: str | None = None
) -> dict[str, Any]:
    """POST one JSON-RPC request to the gateway and return the parsed response."""

    async def _run() -> dict[str, Any]:
        app, clients = gateway(a_chaos=a_chaos, b_chaos=b_chaos)
        async with contextlib.AsyncExitStack() as stack:
            for client in clients:
                await stack.enter_async_context(client)
            # ASGITransport speaks only the `http` scope — it never runs the
            # ASGI lifespan protocol. The SDK's streamable-HTTP app starts its
            # session manager's task group in lifespan, so without this the app
            # serves requests while uninitialised: "Task group is not initialized".
            await stack.enter_async_context(app.router.lifespan_context(app))

            transport = httpx.ASGITransport(app=app)
            # The SDK validates the Host header as DNS-rebinding protection and
            # `build_app` allows 127.0.0.1 by default. A made-up hostname would
            # be testing against a security control rather than through it.
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as agent:
                response = await agent.post("/mcp", json=body, headers=MCP_HEADERS)
                return _parse(response)
        raise AssertionError("unreachable")

    return anyio.run(_run)


def _parse(response: httpx.Response) -> dict[str, Any]:
    """Read a JSON body, or the first data frame of an SSE stream."""
    text = response.text
    if text.lstrip().startswith("{"):
        parsed: dict[str, Any] = response.json()
        return parsed
    for line in text.splitlines():
        if line.startswith("data:"):
            frame: dict[str, Any] = json.loads(line[len("data:") :].strip())
            return frame
    msg = f"could not parse gateway response: {text[:200]!r}"
    raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Merged catalogue
# ---------------------------------------------------------------------------


def test_gateway_serves_a_merged_qualified_catalogue() -> None:
    """An agent asks once and gets every upstream's tools, disambiguated."""
    body = call_gateway(rpc("tools/list"))

    names = [tool["name"] for tool in body["result"]["tools"]]
    assert names == [
        "mock-a__read_document",
        "mock-a__search",
        "mock-a__create_ticket",
        "mock-b__search",
        "mock-b__summarize",
        "mock-b__list_channels",
    ]


def test_catalogue_preserves_the_wire_field_name_for_schema() -> None:
    """Through two conversions, `inputSchema` must survive as `inputSchema`.

    Our upstream model parses it, the SDK model re-serialises it. If either
    alias were wrong the tool would reach the agent with no schema — a silent
    failure a real client experiences as an unusable tool.
    """
    body = call_gateway(rpc("tools/list"))

    first = body["result"]["tools"][0]
    assert "inputSchema" in first
    assert first["inputSchema"]["type"] == "object"


def test_gateway_proxies_a_successful_tool_call() -> None:
    body = call_gateway(
        rpc(
            "tools/call",
            {"name": "mock-a__read_document", "arguments": {"path": "runbooks/deploy.md"}},
        )
    )

    result = body["result"]
    assert "Deploy runbook" in result["content"][0]["text"]
    assert not result.get("isError", False)


def test_the_colliding_search_tools_route_to_different_upstreams() -> None:
    """End to end, through qualification and back — the collision is resolved."""
    from_a = call_gateway(
        rpc("tools/call", {"name": "mock-a__search", "arguments": {"query": "deploy"}})
    )
    from_b = call_gateway(
        rpc("tools/call", {"name": "mock-b__search", "arguments": {"query": "payment"}})
    )

    assert from_a["result"]["content"][0]["text"].startswith("mock-a search results:")
    assert from_b["result"]["content"][0]["text"].startswith("mock-b search results:")


def test_execution_failure_is_proxied_as_a_result_not_an_error() -> None:
    """The distinction has to survive the whole path, not just one layer.

    Upstream reports isError; the gateway hands that to the agent as a result.
    Turning it into a protocol error would say the tool is broken when in fact
    its argument was wrong and a different one would work.
    """
    body = call_gateway(
        rpc("tools/call", {"name": "mock-a__read_document", "arguments": {"path": "nope.md"}})
    )

    assert "error" not in body
    assert body["result"]["isError"] is True
    assert "no such document" in body["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# Partial failure and the taxonomy
# ---------------------------------------------------------------------------


def test_one_failing_upstream_still_serves_the_other() -> None:
    """The availability decision, visible from the client's side."""
    body = call_gateway(rpc("tools/list"), a_chaos="error")

    names = [tool["name"] for tool in body["result"]["tools"]]
    assert names == ["mock-b__search", "mock-b__summarize", "mock-b__list_channels"]


def test_every_upstream_failing_is_an_error_not_an_empty_catalogue() -> None:
    """An empty list would tell the agent it has no tools and let it proceed."""
    body = call_gateway(rpc("tools/list"), a_chaos="error", b_chaos="error")

    assert "error" in body
    assert body["error"]["data"]["recoverable"] is False


def test_malformed_upstream_response_is_not_recoverable() -> None:
    body = call_gateway(rpc("tools/list"), a_chaos="malformed", b_chaos="malformed")

    assert body["error"]["data"]["recoverable"] is False


def test_unknown_tool_is_rejected() -> None:
    body = call_gateway(rpc("tools/call", {"name": "mock-a__no_such_tool", "arguments": {}}))

    assert "error" in body
    assert body["error"]["data"]["upstream_code"] == -32602


def test_unknown_upstream_is_rejected() -> None:
    """A qualified name naming an upstream that is not configured."""
    body = call_gateway(rpc("tools/call", {"name": "mock-z__search", "arguments": {}}))

    assert "error" in body
    assert body["error"]["data"]["configured"] == ["mock-a", "mock-b"]
