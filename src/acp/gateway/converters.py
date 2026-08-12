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


APPROVAL_META_KEY = "dev.agent-control-plane/approval"
"""Namespaced, like every `_meta` key this project writes.

The spec's own keys live under `io.modelcontextprotocol/`; anything a gateway
invents needs a namespace of its own or it collides with the next revision.
"""


def to_input_required(*, token: str, expires_in: float) -> types.InputRequiredResult:
    """The "waiting for a human" answer, carrying the token to retry with.

    **`input_requests` is deliberately left empty, and that is a security
    decision rather than an omission.**

    MRTR's `input_requests` asks the *client* to satisfy something — sampling,
    roots, or an elicitation put to its user. Using an `ElicitRequest` here to
    ask "approve this delete?" is the obvious move and it is theatre: **the
    client is the agent.** An agent that has been talked into deleting the
    production dataset by a poisoned document is exactly the agent that will
    answer its own elicitation "yes", and the whole premise of this gateway's
    Phase 5 is that agents read hostile text. A boundary the caller can satisfy
    is not a boundary (SECURITY.md, and the same lesson `Mcp-Name` taught).

    So the approval decision arrives on a channel the agent cannot reach
    (task 55), and this result says only *wait, and come back with this*. For
    the same reason `on_call_tool` reads `request_state` from a retry and
    **discards `input_responses` entirely**: nothing the caller sends can
    authorise the call it is asking about.

    What the caller does get is enough to be useful: that approval is pending
    and roughly how long it has. The expiry is safe to disclose for the reason
    `retry_after` is (task 42) — it describes only the limit they are already
    inside. The deciding rule is *not* disclosed, for the reason
    `PolicyDeniedError` withholds it: which rule stopped a call is an oracle a
    caller can map one request at a time.
    """
    # Constructed by *field* name rather than through `model_validate` on a
    # wire-shaped dict — a deliberate departure from the rest of this module,
    # and the reason is measurement. The convention above exists so this code
    # depends on the specification's wire contract instead of the SDK's internal
    # names; here the SDK's field names are the half that was actually verified
    # against the installed version (`request_state`, `meta`) and the aliases
    # are the half that was not.
    #
    # That asymmetry matters because of *how* this fails: pydantic ignores an
    # unrecognised key, so a wrong alias would produce a perfectly valid
    # `input_required` with the token silently missing — an approval the client
    # can never answer, and a converter test that passes. `to_wire` below turns
    # the remaining guess into an assertion instead of a hope.
    return types.InputRequiredResult(
        # Set explicitly even though it is this type's only legal value and
        # its default. The SDK dumps the handler's result and then reads
        # `resultType` back to pick the result surface, and a field left at
        # its default is dropped from that dump - which leaves the union
        # with no discriminator and silently falls back to CallToolResult.
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
    """What a client actually receives, for the test that checks it arrives.

    Exists because the failure this guards is silent. A key the SDK does not
    recognise is dropped rather than rejected, so "the token reached the caller"
    is not something construction can tell you — only serialisation can, and
    only if somebody looks.
    """
    return result.model_dump(by_alias=True, exclude_none=True)
