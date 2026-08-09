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
from acp.upstream.models import CallToolResult, ListToolsResult


@runtime_checkable
class Credentials(Protocol):
    """Whatever can produce an ``Authorization`` value for an upstream call.

    A structural type, and deliberately not an import of ``acp.identity``. The
    upstream client's business is HTTP and JSON-RPC; giving it a concrete
    dependency on token exchange would make every test of the transport need an
    authorization server, and would put an identity import in the one package
    that should be usable without one.

    What it receives is a name and an audience — never a principal, never a
    token. The client cannot forward an inbound credential because it is not
    holding one.
    """

    async def authorization_for(self, upstream: str, audience: str) -> str | None:
        """The header value for this call, or ``None`` to send none."""
        ...


@runtime_checkable
class Upstream(Protocol):
    """One upstream MCP server, however it is reached."""

    @property
    def config(self) -> UpstreamConfig:
        """Declared as a property so both a plain attribute and a computed one
        satisfy it — the concrete client stores it, the wrappers delegate."""
        ...

    async def list_tools(self) -> ListToolsResult:
        """Fetch this upstream's tool catalogue, with its freshness hints."""
        ...

    async def invalidate(self) -> None:
        """Discard anything cached about this upstream.

        On the protocol rather than only on the caching wrapper, because the
        health monitor has to be able to force a real request without knowing
        which layers are present. A probe answered from cache reports on a
        conversation that happened minutes ago.
        """
        ...

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Invoke one tool. A tool that runs and fails returns ``is_error``."""
        ...

    async def aclose(self) -> None:
        """Release whatever resources this upstream holds."""
        ...
