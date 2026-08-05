"""Translation between the gateway's internal models and the MCP SDK's types.

This module is the seam described in ADR 0005. Outbound (`acp.upstream`) is
hand-rolled and parses upstream responses into our own models; inbound uses the
SDK's types. Everything the gateway does in between — merging, namespacing,
policy, filtering — operates on *our* models, never the SDK's, so the two halves
stay independent.

**Why `model_validate` on alias-keyed dicts rather than keyword construction.**
The SDK's models use snake_case field names with camelCase serialisation
aliases (`input_schema` / `inputSchema`, `is_error` / `isError`). Building from
a wire-shaped dict means this code depends only on the *wire* contract, which is
fixed by the specification, rather than on the SDK's internal field names, which
are its own choice and could change between releases. It also means the
conversion is inspectable: what goes in is exactly what a real MCP client would
see on the wire.
"""

from __future__ import annotations

from typing import Any

from mcp import types

from acp.upstream.models import CallToolResult, ToolDefinition


def to_mcp_tool(tool: ToolDefinition) -> types.Tool:
    """Convert one upstream tool definition into an SDK ``Tool``."""
    payload: dict[str, Any] = {
        "name": tool.name,
        "inputSchema": tool.input_schema,
    }
    # `description` is optional in the SDK model; sending an empty string where
    # the upstream had none would be inventing content the upstream never gave.
    if tool.description:
        payload["description"] = tool.description
    return types.Tool.model_validate(payload)


def to_mcp_call_tool_result(result: CallToolResult) -> types.CallToolResult:
    """Convert an upstream tool result into an SDK ``CallToolResult``.

    Content blocks are passed through as raw wire dicts rather than being
    reconstructed field by field. MCP defines several content types and a spec
    revision can add more; rebuilding only the ones we recognise would silently
    drop image and resource blocks that the caller is entitled to receive.

    ``is_error`` is preserved rather than raised. A tool that ran and failed is
    a *result* — see the note in ``acp.upstream.models``.
    """
    return types.CallToolResult.model_validate(
        {
            "content": [
                block.model_dump(by_alias=True, exclude_none=True) for block in result.content
            ],
            "isError": result.is_error,
        }
    )
