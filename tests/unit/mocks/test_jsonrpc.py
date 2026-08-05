"""Unit tests for the JSON-RPC envelope invariants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from acp.mocks.jsonrpc import (
    METHOD_NOT_FOUND,
    CallToolResult,
    JsonRpcErrorObject,
    JsonRpcResponse,
    TextContent,
    ToolDefinition,
    call_tool_result,
    error_response,
)


def test_response_rejects_both_result_and_error() -> None:
    """JSON-RPC 2.0 forbids it, and a real client would reject the message."""
    with pytest.raises(ValidationError, match="exactly one"):
        JsonRpcResponse(
            id=1, result={"ok": True}, error=JsonRpcErrorObject(code=-1, message="nope")
        )


def test_response_rejects_neither_result_nor_error() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        JsonRpcResponse(id=1)


def test_result_only_response_is_valid() -> None:
    assert JsonRpcResponse(id=1, result={"ok": True}).error is None


def test_error_response_helper_sets_code_and_message() -> None:
    response = error_response(42, METHOD_NOT_FOUND, "unknown method: foo")

    assert response.id == 42
    assert response.error is not None
    assert response.error.code == METHOD_NOT_FOUND


def test_tool_definition_serialises_schema_as_input_schema() -> None:
    definition = ToolDefinition(name="t", description="d", input_schema={"type": "object"})

    assert definition.model_dump(by_alias=True)["inputSchema"] == {"type": "object"}


def test_call_tool_result_serialises_is_error_as_camel_case() -> None:
    payload = call_tool_result(CallToolResult(content=[TextContent(text="x")], is_error=True))

    assert payload["isError"] is True
    assert payload["content"][0]["type"] == "text"
