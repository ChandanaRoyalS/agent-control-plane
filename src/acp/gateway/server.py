"""The gateway's inbound half: the MCP server that agents connect to.

Built on the SDK's low-level ``Server`` rather than the high-level
``MCPServer`` — see ADR 0005. The distinction matters more than it looks.
``MCPServer`` registers tools statically with decorators, which models a tool
*provider*. A gateway is a tool *broker*: its catalogue is computed on every
request, merged from live upstreams and (from task 35) filtered by what the
calling principal is entitled to see. ``Server`` takes ``on_list_tools`` and
``on_call_tool`` as per-request async handlers, which is exactly that shape.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette

from acp import __version__
from acp.exceptions import ACPError, PolicyDeniedError
from acp.gateway.converters import to_mcp_call_tool_result, to_mcp_tool
from acp.gateway.registry import UpstreamRegistry
from acp.identity import (
    AuthenticationMiddleware,
    ProtectedResource,
    TokenValidator,
    metadata_route,
)
from acp.identity.principal import current_principal
from acp.observability import RequestContextMiddleware
from acp.policy import Policy, enforce_call, visible_tools

logger = logging.getLogger(__name__)

SERVER_NAME = "agent-control-plane"

DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")
"""Hosts accepted when nothing else is configured.

The SDK enables DNS-rebinding protection by default and its allow-list has *no*
default value, so an unconfigured server rejects every request. That is the
right default for a security control — deny until told otherwise — but it means
the allow-list is a required decision rather than an optional one.
"""


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


def build_server(registry: UpstreamRegistry, *, policy: Policy | None = None) -> Server[None]:
    """Build an MCP server that brokers for the registry's upstreams.

    The handlers are closures over ``registry`` rather than methods on a class
    because the SDK wants plain callables, and because there is no per-server
    mutable state to hold — every request is answered from the upstreams as they
    are *now*, which is the property that makes health-driven catalogue
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
        catalogue = await registry.list_tools()

        if policy is not None:
            # Show only what this principal may call. Fail-closed, like
            # on_call_tool: a loaded policy with no principal sees an
            # empty catalogue, not the full one.
            principal = current_principal()
            visible = (
                visible_tools(policy, principal, catalogue.tools) if principal is not None else []
            )
            catalogue = replace(catalogue, tools=visible)

        if catalogue.is_total_failure:
            # Nothing answered. Returning an empty catalogue would tell the
            # agent it has no tools, which is indistinguishable from a correctly
            # configured gateway with nothing attached — and would send it off
            # to attempt the task without them. An error says "ask again later".
            first = next(iter(catalogue.failures.values()))
            raise to_mcp_error(first)

        # Withdrawals are deliberately not logged here. They were logged once,
        # by the health monitor, when the upstream changed state — logging them
        # again on every request would produce a warning per request for as long
        # as the outage lasts.
        for name, exc in catalogue.failures.items():
            # Partial failure is served, not raised — see UpstreamRegistry.
            logger.warning(
                "gateway.upstream_degraded",
                extra={
                    "upstream": name,
                    "operation": "tools/list",
                    "error": type(exc).__name__,
                    "reason": exc.message,
                    "served_tools": len(catalogue.tools),
                    "withdrawn": sorted(catalogue.withdrawn),
                },
            )

        # The gateway's own freshness hint, composed from the upstreams that
        # contributed. An agent's prompt contains this list, so a catalogue that
        # changes every turn misses the model provider's prompt cache and the
        # whole prompt is billed again — stability here is a cost decision, not
        # only a latency one.
        return types.ListToolsResult(
            tools=[to_mcp_tool(tool) for tool in catalogue.tools],
            ttl_ms=catalogue.ttl_ms,
            cache_scope="public" if catalogue.cache_scope == "public" else "private",
        )

    async def on_call_tool(
        _ctx: ServerRequestContext[None, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        if policy is not None:
            # Fail-closed: a loaded policy means authorization is
            # expected. A missing principal here is a misconfiguration
            # (policy set, auth not), and must deny rather than permit.
            principal = current_principal()
            if principal is None:
                raise to_mcp_error(PolicyDeniedError("this call was not permitted"))
            try:
                enforce_call(policy, principal, params.name)
            except ACPError as exc:
                raise to_mcp_error(exc) from exc
        try:
            result = await registry.call_tool(params.name, params.arguments or {})
        except ACPError as exc:
            raise to_mcp_error(exc) from exc
        return to_mcp_call_tool_result(result)

    return Server(
        SERVER_NAME,
        version=__version__,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_app(
    registry: UpstreamRegistry,
    *,
    allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
    allowed_origins: Sequence[str] = (),
    validator: TokenValidator | None = None,
    resource: ProtectedResource | None = None,
    policy: Policy | None = None,
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

    ``resource``, when given, adds the RFC 9728 metadata route *and* is what the
    authentication middleware exempts. One object doing both is the point: the
    only unauthenticated path in the gateway is derived from the document being
    served there rather than from a list of paths kept in step by hand.
    """
    security = TransportSecuritySettings(
        allowed_hosts=list(allowed_hosts),
        allowed_origins=list(allowed_origins),
    )
    app = build_server(registry, policy=policy).streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
    if resource is not None:
        # Inserted at the front rather than appended, because the SDK is free to
        # mount its transport at the root — and a route added after a catch-all
        # mount is a route that never matches. This is one line of defence
        # against a silent 404 on the one endpoint whose entire job is to be
        # findable by a client that knows nothing else about this gateway.
        #
        # The middleware receives the same object, which is what makes this
        # route reachable without a token: the exemption is `metadata_path`
        # taken from `resource`, so serving it and exempting it cannot come
        # apart. See `acp.identity.resource`.
        app.router.routes.insert(0, metadata_route(resource))
    # Added to Starlette's own stack rather than by wrapping the app, so the
    # returned object is still a Starlette instance — `app.router` and the
    # lifespan context are part of this function's contract and the tests use
    # them. Safe to call here because Starlette builds its middleware stack
    # lazily, on the first request rather than at construction.
    #
    # Order matters, and Starlette's is the reverse of the reading order:
    # `add_middleware` inserts at the front, so the *last* one added runs
    # outermost. Authentication is added first and therefore runs *inside* the
    # request-context middleware — which is what makes a rejected request still
    # carry a request ID in its log line. A 401 nobody can correlate is a 401
    # nobody can investigate.
    app.add_middleware(AuthenticationMiddleware, validator=validator, resource=resource)
    app.add_middleware(RequestContextMiddleware)
    return app
