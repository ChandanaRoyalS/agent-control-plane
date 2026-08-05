"""Integration tests: the gateway's outbound client against the mock upstreams.

This is the first test that exercises both halves of the wire format at once —
``acp.mocks.jsonrpc`` serialising and ``acp.upstream.models`` parsing. They are
independent implementations, so agreement here is evidence rather than
tautology.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.exceptions import (
    UpstreamProtocolError,
    UpstreamRejectedError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from acp.mocks import mock_a, mock_b
from acp.mocks.chaos import CHAOS_MODE_HEADER, CHAOS_PARAM_HEADER
from acp.upstream import UpstreamClient, UpstreamConfig

pytestmark = pytest.mark.integration


def make_client(
    app: Starlette,
    name: str = "mock-a",
    *,
    chaos: str | None = None,
    chaos_param: str | None = None,
) -> UpstreamClient:
    """An UpstreamClient wired to an ASGI app instead of a socket.

    Chaos headers are attached to the transport rather than passed per call,
    because the gateway's own API has no notion of chaos — the upstream is
    simply misbehaving, which is exactly the situation being simulated.
    """
    headers: dict[str, str] = {}
    if chaos is not None:
        headers[CHAOS_MODE_HEADER] = chaos
    if chaos_param is not None:
        headers[CHAOS_PARAM_HEADER] = chaos_param

    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), headers=headers)
    return UpstreamClient(UpstreamConfig(name=name, url="http://mock/mcp"), http)


def run(coro_fn: Any) -> Any:
    return anyio.run(coro_fn)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_list_tools_parses_the_catalogue() -> None:
    async def _run() -> list[str]:
        async with make_client(mock_a.app) as client:
            return [t.name for t in await client.list_tools()]

    assert run(_run) == ["read_document", "search", "create_ticket"]


def test_list_tools_parses_the_input_schema_alias() -> None:
    """The wire sends ``inputSchema``; the model exposes ``input_schema``.

    This is the cross-check that matters: the mock serialises with one alias
    and the client parses with another, written independently. If either got
    the wire name wrong, this fails.
    """

    async def _run() -> dict[str, Any]:
        async with make_client(mock_a.app) as client:
            tools = await client.list_tools()
            return next(t for t in tools if t.name == "read_document").input_schema

    schema = run(_run)
    assert schema["type"] == "object"
    assert "path" in schema["properties"]


def test_call_tool_returns_content() -> None:
    async def _run() -> Any:
        async with make_client(mock_a.app) as client:
            return await client.call_tool("read_document", {"path": "runbooks/deploy.md"})

    result = run(_run)
    assert result.is_error is False
    assert "Deploy runbook" in result.text()


def test_call_tool_on_the_other_upstream() -> None:
    async def _run() -> Any:
        async with make_client(mock_b.app, name="mock-b") as client:
            return await client.call_tool("summarize", {"channel": "incidents"})

    assert "payment API" in run(_run).text()


# ---------------------------------------------------------------------------
# Execution failure is a *result*, not an exception
# ---------------------------------------------------------------------------


def test_tool_execution_failure_is_returned_not_raised() -> None:
    """The distinction the whole error taxonomy rests on.

    The request was valid and the upstream is healthy — the tool simply failed.
    Raising here would tell the agent the tool is broken, when what actually
    happened is that its argument was wrong and a different argument would work.
    """

    async def _run() -> Any:
        async with make_client(mock_a.app) as client:
            return await client.call_tool("read_document", {"path": "does-not-exist.md"})

    result = run(_run)
    assert result.is_error is True
    assert "no such document" in result.text()


# ---------------------------------------------------------------------------
# Protocol rejections raise, and carry the upstream's own code
# ---------------------------------------------------------------------------


def test_unknown_tool_raises_rejected_with_the_upstream_code() -> None:
    async def _run() -> None:
        async with make_client(mock_a.app) as client:
            await client.call_tool("no_such_tool")

    with pytest.raises(UpstreamRejectedError) as exc_info:
        run(_run)

    assert exc_info.value.upstream_code == -32602  # INVALID_PARAMS
    assert exc_info.value.upstream == "mock-a"
    assert exc_info.value.recoverable is False


def test_chaos_error_mode_raises_rejected() -> None:
    async def _run() -> None:
        async with make_client(mock_a.app, chaos="error") as client:
            await client.list_tools()

    with pytest.raises(UpstreamRejectedError) as exc_info:
        run(_run)

    assert exc_info.value.upstream_code == -32050


# ---------------------------------------------------------------------------
# Transport and protocol failures
# ---------------------------------------------------------------------------


def test_malformed_json_raises_protocol_error() -> None:
    """Not recoverable: retrying broken JSON produces the same broken JSON."""

    async def _run() -> None:
        async with make_client(mock_a.app, chaos="malformed") as client:
            await client.list_tools()

    with pytest.raises(UpstreamProtocolError) as exc_info:
        run(_run)

    assert exc_info.value.recoverable is False
    assert exc_info.value.details["upstream"] == "mock-a"


def test_connection_dropped_mid_response_raises_unavailable() -> None:
    """A dropped connection is "could not complete the exchange", not "answered badly".

    Uses ``MockTransport`` raising ``httpx.RemoteProtocolError`` — which is what
    httpx actually produces when a real socket dies mid-body — rather than the
    mock's ``disconnect`` chaos mode. ADR 0004 records why: the in-process ASGI
    transport propagates the app's own exception instead of translating it into
    an httpx error, so it cannot faithfully reproduce socket-level behaviour.

    The message below is not invented: it is what httpx actually produced when
    the ``disconnect`` chaos mode was run against a real uvicorn server over a
    real socket. See ADR 0005, "Verified, not assumed".
    """

    async def handler(request: httpx.Request) -> httpx.Response:
        msg = "peer closed connection without sending complete message body"
        raise httpx.RemoteProtocolError(msg, request=request)

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()

    with pytest.raises(UpstreamUnavailableError) as exc_info:
        run(_run)

    assert exc_info.value.recoverable is True


def test_read_timeout_raises_timeout_error_and_is_recoverable() -> None:
    """A hung upstream must surface as a timeout, distinctly from other failures.

    Recoverable is True on purpose: a timeout says nothing about whether the
    request was valid, so the agent retrying is reasonable — unlike a malformed
    response, where retrying just burns budget.

    Uses ``MockTransport`` rather than the mock's ``hang`` chaos mode because
    httpx timeouts are enforced at the socket layer, and ``ASGITransport`` runs
    the app in-process without one — a hang there blocks for its full duration
    and then succeeds.

    Against a real uvicorn server the mock's ``hang`` mode with a 1s read timeout
    does raise this error, in 1.36s. See ADR 0005, "Verified, not assumed".
    """

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out waiting for response body", request=request)

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()

    with pytest.raises(UpstreamTimeoutError) as exc_info:
        run(_run)

    assert exc_info.value.recoverable is True
    assert exc_info.value.upstream == "mock-a"


def test_timeout_is_distinguished_from_unavailable() -> None:
    """Both are transport failures, but they mean different things downstream.

    The circuit breaker in task 14 should weight a refused connection
    differently from a slow response, which it cannot do if both arrive as the
    same exception type.
    """
    assert not issubclass(UpstreamTimeoutError, UpstreamUnavailableError)
    assert not issubclass(UpstreamUnavailableError, UpstreamTimeoutError)


def test_oversized_response_still_parses() -> None:
    """A huge but valid response is not an error at this layer.

    Size limits belong to a later task, and conflating "large" with "malformed"
    would make that task impossible to implement correctly.
    """

    async def _run() -> list[str]:
        async with make_client(mock_a.app, chaos="oversized", chaos_param="20000") as client:
            return [t.name for t in await client.list_tools()]

    assert len(run(_run)) == 3


# ---------------------------------------------------------------------------
# The routable headers from the 2026-07-28 revision
# ---------------------------------------------------------------------------


def test_outbound_requests_carry_the_routable_headers() -> None:
    """`Mcp-Method` and `Mcp-Name` must be set for gateway-layer routing.

    Captured at the transport rather than asserted on the mock, because the
    mock deliberately ignores them — what matters is that the gateway emits
    them.
    """
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()
            await c.call_tool("read_document", {"path": "x"})

    run(_run)

    assert captured[0].headers["mcp-method"] == "tools/list"
    assert "mcp-name" not in captured[0].headers

    assert captured[1].headers["mcp-method"] == "tools/call"
    assert captured[1].headers["mcp-name"] == "read_document"


def test_outbound_requests_carry_protocol_version_in_meta() -> None:
    """The stateless revision has no handshake, so every request declares itself."""
    captured: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()

    run(_run)

    assert captured[0]["_meta"]["protocolVersion"] == "2026-07-28"
    assert captured[0]["_meta"]["client"]["name"] == "agent-control-plane"


def test_request_ids_increment() -> None:
    """Reused ids make a packet capture impossible to correlate."""
    captured: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()
            await c.list_tools()

    run(_run)

    assert [body["id"] for body in captured] == [1, 2]


# ---------------------------------------------------------------------------
# Responses that are valid JSON but not valid JSON-RPC
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"jsonrpc": "2.0", "id": 1}, id="neither-result-nor-error"),
        pytest.param({"jsonrpc": "2.0", "id": 1, "result": "not-an-object"}, id="scalar-result"),
        pytest.param({"jsonrpc": "2.0", "id": 1, "error": "not-an-object"}, id="scalar-error"),
        pytest.param(
            {"jsonrpc": "2.0", "id": 1, "error": {"message": "no code"}}, id="error-no-code"
        ),
        pytest.param(["not", "an", "object"], id="top-level-array"),
    ],
)
def test_valid_json_that_is_not_valid_jsonrpc_raises_protocol_error(payload: Any) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()

    with pytest.raises(UpstreamProtocolError):
        run(_run)


def test_http_error_status_raises_unavailable() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream is down")

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()

    with pytest.raises(UpstreamUnavailableError) as exc_info:
        run(_run)

    assert exc_info.value.details["status"] == 503
    assert exc_info.value.recoverable is True


def test_tools_list_without_a_tools_array_raises_protocol_error() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"wrong": []}})

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await c.list_tools()

    with pytest.raises(UpstreamProtocolError, match="tools"):
        run(_run)
