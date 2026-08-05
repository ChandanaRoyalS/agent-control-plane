"""Wire models for what upstream MCP servers send back.

These *parse* incoming payloads, where ``acp.mocks.jsonrpc`` *serialises*
outgoing ones. That asymmetry is deliberate and useful: the two modules are
independent implementations of the same wire format pointing in opposite
directions, so a mistake in one is caught by the other rather than agreed with.

Field names come from the real MCP SDK's ``mcp.types`` — ``inputSchema``,
``isError`` — not from guesswork.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "2026-07-28"
"""The MCP specification revision this gateway speaks. See ADR 0001.

Sent on every outbound request. Under the 2026-07-28 revision the protocol is
stateless — there is no ``initialize`` handshake and no session header — so each
request carries its own version rather than negotiating one up front.
"""


class ContentBlock(BaseModel):
    """One block of a tool result's ``content`` array.

    Deliberately permissive. MCP defines several content types (text, image,
    resource links) and more can be added by a spec revision. A gateway that
    rejects an unfamiliar content type would break tools it has no business
    breaking, so unknown fields are preserved and unknown ``type`` values pass
    through untouched. Only ``text`` is given a typed accessor because that is
    the only one this layer needs to reason about.
    """

    model_config = ConfigDict(extra="allow")

    type: str
    text: str | None = None


class ToolDefinition(BaseModel):
    """One entry in an upstream's ``tools/list`` response."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict, alias="inputSchema")

    @property
    def qualified_name_suffix(self) -> str:
        """The tool half of the ``<upstream>__<tool>`` qualified name (ADR 0003)."""
        return self.name


class CallToolResult(BaseModel):
    """The result of a ``tools/call``.

    ``is_error`` is the MCP convention for *the tool ran and failed* — a
    perfectly valid response, returned to the caller as data. It is emphatically
    not a transport or protocol failure, which arrives as a JSON-RPC ``error``
    and is raised as an ``UpstreamRejectedError`` instead. The gateway's error
    taxonomy depends on keeping these apart.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    content: list[ContentBlock] = Field(default_factory=list)
    is_error: bool = Field(default=False, alias="isError")

    def text(self) -> str:
        """Concatenate every text block, ignoring non-text content."""
        return "\n".join(block.text for block in self.content if block.text is not None)
