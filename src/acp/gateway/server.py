"""The gateway's inbound half: the MCP server that agents connect to.

Built on the SDK's low-level ``Server`` rather than the high-level
``MCPServer`` — see ADR 0005. The distinction matters more than it looks.
``MCPServer`` registers tools statically with decorators, which models a tool
*provider*. A gateway is a tool *broker*: its catalogue is computed on every
request, merged from live upstreams and (from task 37) filtered by what the
calling principal is entitled to see. ``Server`` takes ``on_list_tools`` and
``on_call_tool`` as per-request async handlers, which is exactly that shape.

Scope: this is task 9 — a single upstream, straight through, no namespacing.
Task 10 adds catalogue merging across several upstreams and the
``<upstream>__<tool>`` qualification from ADR 0003.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette

from acp import __version__
from acp.exceptions import ACPError
from acp.gateway.converters import to_mcp_call_tool_result, to_mcp_tool
from acp.upstream import UpstreamClient

SERVER_NAME = "agent-control-plane"


def to_mcp_error(exc: ACPError) -> MCPError:
    """Render a gateway error as an MCP protocol error.

    The taxonomy already knows how to describe itself as a JSON-RPC error
    object, including the ``recoverable`` hint the agent reasons over, so this
    reuses that rather than inventing a second representation. One error shape,
    one place to change it.
    """
    rendered = exc.to_jsonrpc_error()
    # MCPError takes the JSON-RPC error fields directly rather than an
    # ErrorData object. Verified against mcp 2.0.0's signature, not assumed.
    return MCPError(rendered["code"], rendered["message"], rendered["data"])


def build_server(upstream: UpstreamClient) -> Server[None]:
    """Build an MCP server that brokers for a single upstream.

    The handlers are closures over ``upstream`` rather than methods on a class
    because the SDK wants plain callables, and because there is no per-server
    mutable state to hold — every request is answered from the upstream as it
    is *now*, which is the property that makes health-driven catalogue
    withdrawal (task 18) possible later.
    """

    # `_ctx` and `_params` are positional in the SDK's handler contract, so
    # they cannot be dropped. Underscore-prefixed until they are used:
    # `_ctx` carries the HTTP request (headers, auth) and becomes load-bearing
    # in tasks 22 and 35; `_params.cursor` matters once catalogues paginate.
    async def on_list_tools(
        _ctx: ServerRequestContext[None, Any],
        _params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        try:
            tools = await upstream.list_tools()
        except ACPError as exc:
            raise to_mcp_error(exc) from exc
        return types.ListToolsResult(tools=[to_mcp_tool(tool) for tool in tools])

    async def on_call_tool(
        _ctx: ServerRequestContext[None, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        try:
            result = await upstream.call_tool(params.name, params.arguments or {})
        except ACPError as exc:
            raise to_mcp_error(exc) from exc
        return to_mcp_call_tool_result(result)

    return Server(
        SERVER_NAME,
        version=__version__,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")
"""Hosts accepted when nothing else is configured.

The SDK enables DNS-rebinding protection by default and its allow-list has *no*
default value, so an unconfigured server rejects every request. That is the
right default for a security control — deny until told otherwise — but it means
the allow-list is a required decision rather than an optional one.
"""


def build_app(
    upstream: UpstreamClient,
    *,
    allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
    allowed_origins: Sequence[str] = (),
) -> Starlette:
    """Build the ASGI application agents connect to.

    ``stateless_http=True`` matches ADR 0001: the 2026-07-28 revision removed
    the initialize handshake and the session header, so there is no session to
    keep and any instance can serve any request.

    ``json_response=True`` returns a plain JSON body rather than an SSE stream
    for unary responses. Simpler to proxy, simpler to test, and nothing in the
    gateway's current surface streams.

    ``allowed_hosts`` and ``allowed_origins`` drive the SDK's DNS-rebinding
    protection: it rejects any ``Host`` it was not told to expect, which defends
    a locally-bound server against a malicious web page resolving a hostname to
    a loopback address. Defaults cover local development; deployment behind a
    real hostname must pass its own list, and that becomes config in task 11.
    """
    security = TransportSecuritySettings(
        allowed_hosts=list(allowed_hosts),
        allowed_origins=list(allowed_origins),
    )
    return build_server(upstream).streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
