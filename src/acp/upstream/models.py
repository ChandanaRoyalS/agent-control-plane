"""Wire models for what upstream MCP servers send back.

Independent of ``acp.mocks.jsonrpc``, which serialises the same format, so a
mistake in one is caught by the other. Field names follow the SDK's ``mcp.types``.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "2026-07-28"
"""The MCP revision spoken (ADR 0001); stateless, so sent on every request."""


class ContentBlock(BaseModel):
    """One block of a tool result's ``content`` array.

    Permissive: unknown fields and ``type`` values pass through untouched.
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


class ListToolsResult(BaseModel):
    """An upstream's ``tools/list`` response, freshness hints included.

    ``ttlMs`` and ``cacheScope`` are top-level and default to no caching
    (``0``, ``private``). ``cacheScope`` is an authorization boundary: only
    ``public`` entries may be shared across callers.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    tools: list[ToolDefinition] = Field(default_factory=list)
    ttl_ms: int = Field(default=0, ge=0, alias="ttlMs")
    cache_scope: Literal["public", "private"] = Field(default="private", alias="cacheScope")

    @property
    def is_shareable(self) -> bool:
        """Whether this response may be held in a cache shared between callers."""
        return self.cache_scope == "public" and self.ttl_ms > 0


class CallToolResult(BaseModel):
    """The result of a ``tools/call``.

    ``is_error`` means the tool ran and failed, returned as data. A JSON-RPC
    ``error`` is raised as ``UpstreamRejectedError`` instead.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    content: list[ContentBlock] = Field(default_factory=list)
    is_error: bool = Field(default=False, alias="isError")

    def text(self) -> str:
        """Concatenate every text block, ignoring non-text content."""
        return "\n".join(block.text for block in self.content if block.text is not None)
