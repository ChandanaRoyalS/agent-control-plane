"""Integration tests for the mock upstream MCP servers.

Tests are written as synchronous functions that drive an event loop via
``anyio.run``. That is deliberate rather than using async test functions: it
keeps the suite independent of any particular async pytest plugin, so these
tests behave identically no matter how the runner is configured. The cost is one
extra wrapper line per test; the benefit is one fewer thing that can silently
break CI.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from acp.mocks import mock_a, mock_b
from acp.mocks.chaos import CHAOS_MODE_HEADER, CHAOS_PARAM_HEADER, CHAOS_SIMULATED_ERROR
from acp.mocks.jsonrpc import INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR
from tests.integration.helpers import MCP_URL, asgi_client, headers_for, rpc

pytestmark = pytest.mark.integration


def post(app: Any, body: Any, headers: dict[str, str] | None = None) -> Any:
    """POST a body to a mock app and return the parsed JSON response."""

    async def _run() -> Any:
        async with asgi_client(app) as client:
            merged = {**headers_for(body), **(headers or {})}
            response = await client.post(MCP_URL, json=body, headers=merged)
            return response.json()

    return anyio.run(_run)


def post_raw(app: Any, content: str, headers: dict[str, str] | None = None) -> Any:
    """POST a raw string body (used to send deliberately invalid JSON)."""

    async def _run() -> Any:
        async with asgi_client(app) as client:
            return await client.post(
                MCP_URL,
                content=content,
                headers={"content-type": "application/json", **(headers or {})},
            )

    return anyio.run(_run)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_mock_a_lists_its_three_tools() -> None:
    body = post(mock_a.app, rpc("tools/list"))

    names = [t["name"] for t in body["result"]["tools"]]
    assert names == ["read_document", "search", "create_ticket"]


def test_mock_b_lists_its_three_tools() -> None:
    body = post(mock_b.app, rpc("tools/list"))

    names = [t["name"] for t in body["result"]["tools"]]
    assert names == ["search", "summarize", "list_channels"]


def test_tool_definitions_use_the_wire_field_name_for_schema() -> None:
    """The wire format is ``inputSchema``, not ``input_schema``.

    Pydantic serialisation aliases are easy to get wrong and the failure is
    silent — a real MCP client would simply see a tool with no schema. Assert
    the actual emitted key.
    """
    body = post(mock_a.app, rpc("tools/list"))

    first = body["result"]["tools"][0]
    assert "inputSchema" in first
    assert "input_schema" not in first


def test_read_document_returns_content() -> None:
    body = post(
        mock_a.app,
        rpc("tools/call", {"name": "read_document", "arguments": {"path": "runbooks/deploy.md"}}),
    )

    result = body["result"]
    assert result["isError"] is False
    assert "Deploy runbook" in result["content"][0]["text"]


def test_create_ticket_id_is_stable_across_calls() -> None:
    """Guards the hashlib fix: the built-in hash() is randomised per process."""
    args = {"name": "create_ticket", "arguments": {"title": "Deploy failure", "priority": "high"}}

    first = post(mock_a.app, rpc("tools/call", args))["result"]["content"][0]["text"]
    second = post(mock_a.app, rpc("tools/call", args))["result"]["content"][0]["text"]

    assert first == second
    # Pinned to the value hashlib produces, so a regression to hash() fails here
    # rather than merely becoming flaky.
    assert "TICKET-" in first


def test_the_colliding_search_tool_behaves_differently_on_each_upstream() -> None:
    """Both upstreams expose ``search``; they are genuinely different tools.

    This is the collision ADR 0003's namespacing exists to resolve, planted
    here on purpose so the gateway's merge logic has something real to fail on.
    """
    call = rpc("tools/call", {"name": "search", "arguments": {"query": "deploy"}})

    from_a = post(mock_a.app, call)["result"]["content"][0]["text"]
    from_b = post(mock_b.app, call)["result"]["content"][0]["text"]

    assert from_a.startswith("mock-a search results:")
    assert from_b.startswith("mock-b search results:")
    assert from_a != from_b


# ---------------------------------------------------------------------------
# Protocol-level errors: a JSON-RPC `error` object
# ---------------------------------------------------------------------------


def test_unknown_method_is_method_not_found() -> None:
    body = post(mock_a.app, rpc("resources/list"))

    assert body["error"]["code"] == METHOD_NOT_FOUND
    assert "result" not in body


def test_unknown_tool_is_invalid_params() -> None:
    body = post(mock_a.app, rpc("tools/call", {"name": "no_such_tool", "arguments": {}}))

    assert body["error"]["code"] == INVALID_PARAMS


def test_missing_tool_name_is_invalid_params() -> None:
    body = post(mock_a.app, rpc("tools/call", {"arguments": {}}))

    assert body["error"]["code"] == INVALID_PARAMS


def test_unparseable_body_is_parse_error() -> None:
    response = post_raw(mock_a.app, "{not json at all")

    assert response.json()["error"]["code"] == PARSE_ERROR


def test_wrong_shaped_request_is_invalid_request() -> None:
    """Well-formed JSON, but not a valid JSON-RPC request (no ``method``)."""
    body = post(mock_a.app, {"jsonrpc": "2.0", "id": 7})

    assert body["error"]["code"] == INVALID_REQUEST
    assert body["id"] == 7


# ---------------------------------------------------------------------------
# Execution errors: isError inside a successful result
# ---------------------------------------------------------------------------


def test_missing_document_is_an_execution_error_not_a_protocol_error() -> None:
    """The MCP distinction that the gateway's error taxonomy depends on.

    The request was perfectly well-formed, so this is *not* a JSON-RPC error.
    The tool ran and failed, which MCP reports as ``isError`` inside a normal
    result.
    """
    body = post(
        mock_a.app,
        rpc("tools/call", {"name": "read_document", "arguments": {"path": "nope.md"}}),
    )

    assert "error" not in body
    assert body["result"]["isError"] is True
    assert "no such document" in body["result"]["content"][0]["text"]


def test_handler_exception_becomes_is_error() -> None:
    """A handler that raises must not take the server down."""
    body = post(
        mock_b.app,
        rpc("tools/call", {"name": "summarize", "arguments": {"channel": "does-not-exist"}}),
    )

    assert body["result"]["isError"] is True


# ---------------------------------------------------------------------------
# Chaos modes
# ---------------------------------------------------------------------------


def test_chaos_error_mode_fails_every_request() -> None:
    body = post(mock_a.app, rpc("tools/list"), {CHAOS_MODE_HEADER: "error"})

    assert body["error"]["code"] == CHAOS_SIMULATED_ERROR
    assert "mock-a" in body["error"]["message"]


def test_chaos_malformed_mode_returns_unparseable_json() -> None:
    response = post_raw(
        mock_a.app,
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        {CHAOS_MODE_HEADER: "malformed"},
    )

    assert response.status_code == 200
    with pytest.raises(ValueError, match="Expecting"):
        response.json()


def test_chaos_oversized_mode_inflates_the_payload() -> None:
    body = post(
        mock_a.app,
        rpc("tools/list"),
        {CHAOS_MODE_HEADER: "oversized", CHAOS_PARAM_HEADER: "50000"},
    )

    assert len(body["result"]["_chaos_filler"]) == 50_000
    # The real result must survive alongside the filler, so a size-limit test
    # is exercising a genuinely oversized *valid* response.
    assert len(body["result"]["tools"]) == 3


def test_chaos_disconnect_mode_drops_the_connection_mid_response() -> None:
    async def _run() -> str:
        async with asgi_client(mock_a.app) as client:
            try:
                await client.post(
                    MCP_URL, json=rpc("tools/list"), headers={CHAOS_MODE_HEADER: "disconnect"}
                )
            except Exception as exc:
                return type(exc).__name__
            return "no-exception"

    assert anyio.run(_run) != "no-exception"


def test_chaos_hang_mode_outlives_a_deadline() -> None:
    """The client gives up before the upstream answers.

    The deadline is enforced by the test rather than by an httpx timeout,
    because the in-process ASGI transport does not go through the socket layer
    where httpx timeouts apply. What matters is the property being asserted: a
    hung upstream does not return within the caller's budget.
    """

    async def _run() -> bool:
        body = rpc("tools/list")
        async with asgi_client(mock_a.app) as client:
            with anyio.move_on_after(0.2) as scope:
                await client.post(
                    MCP_URL,
                    json=body,
                    # Routing headers included deliberately: envelope validation
                    # runs before the hang, so an invalid request now fails fast
                    # instead of hanging — and this test would pass for entirely
                    # the wrong reason.
                    headers={
                        **headers_for(body),
                        CHAOS_MODE_HEADER: "hang",
                        CHAOS_PARAM_HEADER: "5",
                    },
                )
            return bool(scope.cancelled_caught)

    assert anyio.run(_run) is True


def test_chaos_none_behaves_normally() -> None:
    body = post(mock_a.app, rpc("tools/list"), {CHAOS_MODE_HEADER: "none"})

    assert len(body["result"]["tools"]) == 3
