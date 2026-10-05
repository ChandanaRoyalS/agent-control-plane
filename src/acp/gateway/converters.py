"""Translation between the gateway's internal models and the MCP SDK's types (ADR 0005).

Everything between inbound and outbound runs on our models. Conversions use
``model_validate`` on wire-shaped (camelCase) dicts, so they depend on the spec's wire
contract rather than the SDK's field names.
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
    # Omit rather than invent an empty description.
    if tool.description:
        payload["description"] = tool.description
    return types.Tool.model_validate(payload)


def to_mcp_call_tool_result(result: CallToolResult) -> types.CallToolResult:
    """Convert an upstream tool result into an SDK ``CallToolResult``.

    Content blocks pass through as raw dicts so unrecognised types are not dropped.
    ``is_error`` is preserved as a result (see ``acp.upstream.models``).
    """
    return types.CallToolResult.model_validate(
        {
            "content": [
                block.model_dump(by_alias=True, exclude_none=True) for block in result.content
            ],
            "isError": result.is_error,
        }
    )


APPROVAL_META_KEY = "dev.agent-control-plane/approval"
"""Namespaced `_meta` key, so it cannot collide with spec keys."""


def to_input_required(*, token: str, expires_in: float) -> types.InputRequiredResult:
    """Return the "waiting for a human" result, carrying the token to retry with.

    ``input_requests`` stays empty on purpose: the client is the agent, so an elicitation
    it can answer is no boundary (SECURITY.md). Approval arrives on a channel the agent
    cannot reach, and `on_call_tool` discards ``input_responses``. The expiry is
    disclosed; the deciding rule is not, as for `PolicyDeniedError`.
    """
    # Built by field name, unlike the rest of this module: these SDK names were verified
    # against the installed version, and pydantic silently drops an unknown alias.
    # `to_wire` lets a test assert the token arrives.
    return types.InputRequiredResult(
        # Explicit despite being the default: defaults are dropped from the dump, losing
        # the discriminator and falling back to CallToolResult.
        result_type="input_required",
        request_state=token,
        _meta={
            APPROVAL_META_KEY: {
                "status": "awaiting_human_approval",
                "expiresInSeconds": max(0, int(expires_in)),
                "retry": "call again with the same arguments and this requestState",
            }
        },
    )


def to_wire(result: types.InputRequiredResult) -> dict[str, Any]:
    """Return the serialised result, so a test can check the token survives."""
    return result.model_dump(by_alias=True, exclude_none=True)
