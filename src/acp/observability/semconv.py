"""OpenTelemetry semantic conventions for MCP, expressed as data.

Attribute names and span-naming rules, as plain values with no OpenTelemetry
import. Same reasoning as ``acp.upstream.envelope``: the names are a
specification someone else owns, so they are declared in one place, and getting
one wrong should be a visible mistake rather than a span that silently fails to
group with everything else in the trace.

The conventions used here are the MCP spans defined in OpenTelemetry's GenAI
semantic conventions. Two details from that document shape everything below.

**The gateway is both roles at once.** It receives a request (a ``SERVER`` span)
and makes requests of its own (``CLIENT`` spans). That is the whole reason a
trace through this system is worth looking at: one picture showing the agent's
call, the fan-out to three upstreams, which one was slow, and which one had its
circuit open.

**A tool call is a GenAI ``execute_tool`` operation.** The conventions state that
MCP tool-call spans are compatible with GenAI execute-tool spans, so a
``tools/call`` span carries ``gen_ai.operation.name = "execute_tool"`` and the
tool name. That is what makes these traces legible to tooling built for agent
observability rather than only to MCP-aware readers.
"""

from __future__ import annotations

from typing import Any, Final
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Attribute names
# ---------------------------------------------------------------------------

MCP_METHOD_NAME: Final = "mcp.method.name"
"""Required on every MCP span. `tools/list`, `tools/call`, and so on."""

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
"""Not a standard attribute, and deliberately prefixed with the project's own
namespace rather than invented inside someone else's.

`server.address` already carries the host, but every span in this system is
grouped, filtered and alerted on by *which upstream* rather than by hostname —
two upstreams behind the same host would be indistinguishable otherwise.
"""

EXECUTE_TOOL: Final = "execute_tool"
"""The GenAI operation name for running a tool."""

TRANSPORT_TCP: Final = "tcp"

TOOLS_CALL: Final = "tools/call"
TOOLS_LIST: Final = "tools/list"


# ---------------------------------------------------------------------------
# Span naming
# ---------------------------------------------------------------------------


def span_name(method: str, target: str | None = None) -> str:
    """`{method} {target}`, or just the method when there is no target.

    The convention names a *low-cardinality* span and puts the variable part in
    the target, which is why a tool name is allowed here but arguments are not.
    A span name built from user input is how a tracing backend's index gets
    destroyed.
    """
    return f"{method} {target}" if target else method


# ---------------------------------------------------------------------------
# Attribute sets
# ---------------------------------------------------------------------------

Attributes = dict[str, Any]


def _endpoint(url: str) -> Attributes:
    """`server.address` and `server.port` from an upstream URL.

    The port is filled in from the scheme when the URL omits it, because a span
    that sometimes has a port and sometimes does not cannot be grouped by one.
    """
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
        # A string even when the wire carries an integer: the convention types
        # it as a string, and a backend that receives both cannot filter on it.
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

    The tool name here is the *qualified* name the agent used
    (`mock-a__search`), not the upstream's real one. Both appear in a single
    trace — the qualified name on the server span, the real one on the client
    span beneath it — which makes the gateway's renaming visible rather than
    something a reader has to already know about.
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
    """What to record when an operation fails.

    `error.type` is the exception's class name rather than its message. The
    message is unbounded and often contains the very values that should not be
    in telemetry; the class name is a small closed set that can be grouped and
    alerted on, which is the entire purpose of the attribute.
    """
    attributes: Attributes = {ERROR_TYPE: type(exc).__name__}
    if status_code is not None:
        attributes[RPC_RESPONSE_STATUS_CODE] = str(status_code)
    return attributes
