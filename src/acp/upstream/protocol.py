"""What the gateway needs from an upstream, independent of how it is built.

A structural ``Protocol`` so the registry need not know which wrappers are stacked,
and the wrappers need not subclass ``UpstreamClient`` and its connection pool.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from acp.upstream.config import UpstreamConfig
from acp.upstream.models import CallToolResult, ListToolsResult


@runtime_checkable
class Credentials(Protocol):
    """Whatever can produce an ``Authorization`` value for an upstream call.

    Structural, so this package does not import ``acp.identity``. It receives a name
    and an audience, never an inbound token, so the client cannot forward one.
    """

    async def authorization_for(self, upstream: str, audience: str, resource: str) -> str | None:
        """The header value for this call, or ``None`` to send none."""
        ...


@runtime_checkable
class Upstream(Protocol):
    """One upstream MCP server, however it is reached."""

    @property
    def config(self) -> UpstreamConfig:
        """This upstream's configuration (a property so wrappers can delegate)."""
        ...

    async def list_tools(self) -> ListToolsResult:
        """Fetch this upstream's tool catalogue, with its freshness hints."""
        ...

    async def invalidate(self) -> None:
        """Discard anything cached, so a health probe makes a real request."""
        ...

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Invoke one tool. A tool that runs and fails returns ``is_error``."""
        ...

    async def aclose(self) -> None:
        """Release whatever resources this upstream holds."""
        ...
