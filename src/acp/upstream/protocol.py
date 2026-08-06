"""What the gateway needs from an upstream, independent of how it is built.

The registry brokers between upstreams; it has no business knowing whether the
thing it holds retries, breaks a circuit, or talks straight to a socket. Typing
it against a ``Protocol`` rather than ``UpstreamClient`` makes that explicit and
keeps the decorators (``RetryingUpstreamClient`` now, a circuit-breaking one in
task 14) composable without the registry changing at all.

Structural typing is the right tool here specifically because these wrappers are
*not* subclasses. Making them inherit from ``UpstreamClient`` would drag along a
connection pool and a request path they do not use, purely to satisfy the type
checker.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from acp.upstream.config import UpstreamConfig
from acp.upstream.models import CallToolResult, ToolDefinition


@runtime_checkable
class Upstream(Protocol):
    """One upstream MCP server, however it is reached."""

    @property
    def config(self) -> UpstreamConfig:
        """Declared as a property so both a plain attribute and a computed one
        satisfy it — the concrete client stores it, the wrappers delegate."""
        ...

    async def list_tools(self) -> list[ToolDefinition]:
        """Fetch this upstream's tool catalogue."""
        ...

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Invoke one tool. A tool that runs and fails returns ``is_error``."""
        ...

    async def aclose(self) -> None:
        """Release whatever resources this upstream holds."""
        ...
