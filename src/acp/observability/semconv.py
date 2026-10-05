"""OpenTelemetry GenAI/MCP semantic conventions as plain data, with no OpenTelemetry import.

The gateway emits ``SERVER`` spans for requests it receives and ``CLIENT`` spans for upstream
calls; ``tools/call`` spans carry ``gen_ai.operation.name = "execute_tool"``.
"""

from __future__ import annotations

from typing import Any, Final
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Attribute names
# ---------------------------------------------------------------------------

MCP_METHOD_NAME: Final = "mcp.method.name"
"""Required on every MCP span, e.g. `tools/call`."""

MCP_PROTOCOL_VERSION: Final = "mcp.protocol.version"
MCP_RESOURCE_URI: Final = "mcp.resource.uri"

GEN_AI_OPERATION_NAME: Final = "gen_ai.operation.name"
GEN_AI_TOOL_NAME: Final = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ARGUMENTS: Final = "gen_ai.tool.call.arguments"
GEN_AI_TOOL_CALL_RESULT: Final = "gen_ai.tool.call.result"

JSONRPC_REQUEST_ID: Final = "jsonrpc.request.id"
JSONRPC_PROTOCOL_VERSION: Final = "jsonrpc.protocol.version"
RPC_RESPONSE_STATUS_CODE: Final = "rpc.response.status_code"

ERROR_TYPE: Final = "error.type"

SERVER_ADDRESS: Final = "server.address"
SERVER_PORT: Final = "server.port"
NETWORK_TRANSPORT: Final = "network.transport"

ACP_UPSTREAM: Final = "acp.upstream"
"""Project-specific attribute naming the upstream, since several may share a host."""

EXECUTE_TOOL: Final = "execute_tool"
"""The GenAI operation name for running a tool."""

TRANSPORT_TCP: Final = "tcp"

TOOLS_CALL: Final = "tools/call"
TOOLS_LIST: Final = "tools/list"


# ---------------------------------------------------------------------------
# Span naming
# ---------------------------------------------------------------------------


def span_name(method: str, target: str | None = None) -> str:
    """`{method} {target}`, or the method alone; never built from caller input."""
    return f"{method} {target}" if target else method


def client_target(upstream: str, tool: str | None = None) -> str:
    """Outbound span target: `upstream/tool`, or the upstream alone (e.g. for `tools/list`).

    Uses `/`, not ADR 0003's `__`, because the bare tool name is what crossed the wire.
    """
    return f"{upstream}/{tool}" if tool else upstream


# ---------------------------------------------------------------------------
# Attribute sets
# ---------------------------------------------------------------------------

Attributes = dict[str, Any]


def _endpoint(url: str) -> Attributes:
    """`server.address` and `server.port`, defaulting the port from the scheme."""
    parts = urlsplit(url)
    attributes: Attributes = {}
    if parts.hostname:
        attributes[SERVER_ADDRESS] = parts.hostname
    port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    if port is not None:
        attributes[SERVER_PORT] = port
    return attributes


def client_attributes(
    *,
    method: str,
    upstream: str,
    url: str,
    tool: str | None = None,
    request_id: int | str | None = None,
    protocol_version: str | None = None,
) -> Attributes:
    """Attributes for a span covering one request the gateway *makes*."""
    attributes: Attributes = {
        MCP_METHOD_NAME: method,
        ACP_UPSTREAM: upstream,
        NETWORK_TRANSPORT: TRANSPORT_TCP,
        JSONRPC_PROTOCOL_VERSION: "2.0",
        **_endpoint(url),
    }
    if protocol_version is not None:
        attributes[MCP_PROTOCOL_VERSION] = protocol_version
    if request_id is not None:
        # The convention types it as a string, even for integer IDs.
        attributes[JSONRPC_REQUEST_ID] = str(request_id)
    if tool is not None:
        attributes[GEN_AI_TOOL_NAME] = tool
        attributes[GEN_AI_OPERATION_NAME] = EXECUTE_TOOL
    return attributes


def server_attributes(
    *,
    method: str,
    tool: str | None = None,
    request_id: int | str | None = None,
    protocol_version: str | None = None,
) -> Attributes:
    """Attributes for a span covering one request the gateway *receives*.

    The tool name is the qualified one the agent used (`mock-a__search`).
    """
    attributes: Attributes = {
        MCP_METHOD_NAME: method,
        JSONRPC_PROTOCOL_VERSION: "2.0",
    }
    if protocol_version is not None:
        attributes[MCP_PROTOCOL_VERSION] = protocol_version
    if request_id is not None:
        attributes[JSONRPC_REQUEST_ID] = str(request_id)
    if tool is not None:
        attributes[GEN_AI_TOOL_NAME] = tool
        attributes[GEN_AI_OPERATION_NAME] = EXECUTE_TOOL
    return attributes


def error_attributes(exc: BaseException, status_code: int | None = None) -> Attributes:
    """Failure attributes; `error.type` is the class name, never the (sensitive) message."""
    attributes: Attributes = {ERROR_TYPE: type(exc).__name__}
    if status_code is not None:
        attributes[RPC_RESPONSE_STATUS_CODE] = str(status_code)
    return attributes
