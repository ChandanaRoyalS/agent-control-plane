"""JSON-RPC 2.0 and MCP tool shapes, hand-rolled so the mocks can misbehave on demand (ADR 0004).

The gateway itself uses the SDK (ADR 0002). Field names match the SDK's ``mcp.types``, so real
MCP clients parse these responses.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# JSON-RPC 2.0 envelope
# ---------------------------------------------------------------------------

JsonRpcId = int | str | None


class JsonRpcRequest(BaseModel):
    """An inbound JSON-RPC 2.0 request, strict so gateway bugs surface.

    There is no top-level ``_meta``: the 2026-07-28 envelope lives in ``params._meta``, and
    forbidding extras rejects the old shape.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    jsonrpc: Literal["2.0"] = "2.0"
    id: JsonRpcId = None
    method: str
    params: dict[str, Any] | None = None


class JsonRpcErrorObject(BaseModel):
    """The ``error`` member of a JSON-RPC response, mirroring ``mcp.types.ErrorData``."""

    model_config = ConfigDict(extra="forbid")

    code: int
    message: str
    data: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    """An outbound JSON-RPC 2.0 response with exactly one of ``result`` or ``error``."""

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
HEADER_MISMATCH = -32020
"""A routing header (`Mcp-Method`, `Mcp-Name`, `Mcp-Protocol-Version`) disagrees with the body."""
# Chaos-specific codes live in `chaos.py`.


def error_response(request_id: JsonRpcId, code: int, message: str) -> JsonRpcResponse:
    """Build a well-formed JSON-RPC error response."""
    return JsonRpcResponse(id=request_id, error=JsonRpcErrorObject(code=code, message=message))


# ---------------------------------------------------------------------------
# MCP tool primitives — field names taken from mcp.types, not invented.
# ---------------------------------------------------------------------------


class ToolDefinition(BaseModel):
    """A single entry in a ``tools/list`` response; ``input_schema`` is plain JSON Schema."""

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

    A tool that ran but failed sets ``is_error``; a JSON-RPC ``error`` means it never ran
    (unknown method or tool, bad params). The gateway handles the two differently.
    """

    model_config = ConfigDict(extra="forbid")

    content: list[TextContent]
    is_error: bool = Field(default=False, serialization_alias="isError")


def tool_definitions_result(
    tools: list[ToolDefinition], *, ttl_ms: int = 0, cache_scope: str = "public"
) -> dict[str, Any]:
    """Render a ``tools/list`` result with top-level ``ttlMs`` and ``cacheScope`` (2026-07-28).

    The gateway assumes ``0`` and ``private`` when a hint is absent; these mock defaults differ.
    """
    return {
        "tools": [t.model_dump(by_alias=True) for t in tools],
        "ttlMs": ttl_ms,
        "cacheScope": cache_scope,
    }


def call_tool_result(result: CallToolResult) -> dict[str, Any]:
    """Render a ``tools/call`` result payload."""
    return result.model_dump(by_alias=True)
