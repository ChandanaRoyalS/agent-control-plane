"""JSON-RPC 2.0 and MCP tool-primitive shapes, hand-rolled for the mock fleet.

**Why hand-rolled rather than built on the MCP SDK's server class.** The gateway
itself is built on the SDK (see ADR 0002) — the wire protocol is not something
worth reimplementing for production code. The *mocks* are different: their
entire purpose is to be provoked into misbehaving in precise, controllable ways
(malformed bodies, mid-stream disconnects, oversized payloads), and a
well-behaved SDK server actively gets in the way of that, because it validates
and normalizes exactly the things we need to deliberately break. See
``docs/decisions/0004-hand-roll-mock-protocol-layer.md``.

Field names below are not invented. They are read directly off the installed
``mcp`` SDK's ``mcp.types`` module (``Tool.inputSchema``,
``CallToolResult.content`` / ``isError``, ``TextContent.type`` / ``text``,
``ListToolsResult.tools`` / ``nextCursor``, ``ErrorData.code`` / ``message`` /
``data``) so a real MCP client parses these responses correctly. The 2026-07-28
revision changed session/transport/auth semantics; it did not change the shape
of a tool definition or a tool call result.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# JSON-RPC 2.0 envelope
# ---------------------------------------------------------------------------

JsonRpcId = int | str | None


class JsonRpcRequest(BaseModel):
    """An inbound JSON-RPC 2.0 request.

    ``extra="forbid"`` is deliberate: a strict mock catches gateway bugs that a
    permissive one would silently accept. That makes ``_meta`` an explicit field
    rather than something waved through — under the 2026-07-28 revision there is
    no ``initialize`` handshake, so every request carries its own protocol
    version and client identity in ``_meta``, and a server that rejected it
    would be rejecting valid traffic.

    The field is named ``meta`` with an alias because Pydantic treats
    leading-underscore attribute names as private and would not bind them.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    jsonrpc: Literal["2.0"] = "2.0"
    id: JsonRpcId = None
    method: str
    params: dict[str, Any] | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class JsonRpcErrorObject(BaseModel):
    """The ``error`` member of a JSON-RPC response.

    Mirrors ``mcp.types.ErrorData``: ``code``, ``message``, optional ``data``.
    """

    model_config = ConfigDict(extra="forbid")

    code: int
    message: str
    data: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    """An outbound JSON-RPC 2.0 response.

    Exactly one of ``result`` or ``error`` must be set — never both, never
    neither. This is a JSON-RPC 2.0 requirement, not a style preference, and
    getting it wrong produces a message real MCP clients will reject.
    """

    model_config = ConfigDict(extra="forbid")

    jsonrpc: Literal["2.0"] = "2.0"
    id: JsonRpcId
    result: dict[str, Any] | None = None
    error: JsonRpcErrorObject | None = None

    @model_validator(mode="after")
    def _exactly_one_of_result_or_error(self) -> JsonRpcResponse:
        has_result = self.result is not None
        has_error = self.error is not None
        if has_result == has_error:  # both set, or neither set
            msg = "JsonRpcResponse must set exactly one of `result` or `error`"
            raise ValueError(msg)
        return self


# Standard JSON-RPC 2.0 error codes we actually use in the mocks.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# The implementation-defined range is -32000 to -32099. Chaos-specific codes
# live in `chaos.py` so this module stays purely about the real protocol.


def error_response(request_id: JsonRpcId, code: int, message: str) -> JsonRpcResponse:
    """Build a well-formed JSON-RPC error response."""
    return JsonRpcResponse(id=request_id, error=JsonRpcErrorObject(code=code, message=message))


# ---------------------------------------------------------------------------
# MCP tool primitives — field names taken from mcp.types, not invented.
# ---------------------------------------------------------------------------


class ToolDefinition(BaseModel):
    """A single entry in a ``tools/list`` response.

    ``input_schema`` is a plain JSON Schema dict describing the tool's
    arguments — the same thing a real upstream would generate from type hints.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    input_schema: dict[str, Any] = Field(serialization_alias="inputSchema")


class TextContent(BaseModel):
    """One block of a tool result's content array."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["text"] = "text"
    text: str


class CallToolResult(BaseModel):
    """The ``result`` of a ``tools/call``.

    MCP's convention: a tool that *ran* but failed reports ``is_error: true``
    inside a normal JSON-RPC result, with the failure explained in ``content``.
    A JSON-RPC ``error`` object is reserved for protocol-level failures — an
    unknown method, an unknown tool, malformed params — which never reached
    tool execution at all. The mocks preserve this distinction deliberately,
    because the gateway's error taxonomy (Phase 1, later) has to handle both
    cases differently.
    """

    model_config = ConfigDict(extra="forbid")

    content: list[TextContent]
    is_error: bool = Field(default=False, serialization_alias="isError")


def tool_definitions_result(tools: list[ToolDefinition]) -> dict[str, Any]:
    """Render a ``tools/list`` result payload."""
    return {"tools": [t.model_dump(by_alias=True) for t in tools]}


def call_tool_result(result: CallToolResult) -> dict[str, Any]:
    """Render a ``tools/call`` result payload."""
    return result.model_dump(by_alias=True)
