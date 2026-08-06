"""The set of upstreams the gateway brokers for, and how calls route to them.

Two responsibilities, deliberately kept apart from the server that uses them:

**Merging.** ``list_tools`` fans out to every upstream concurrently and merges
the results under qualified names (ADR 0003). One upstream failing does not fail
the whole catalogue — the failures come back alongside the tools and the caller
decides what to do. A gateway that goes dark because one of five upstreams is
down is worse than one serving the other four, and that is the same principle
health-driven withdrawal (task 18) will build on.

**Routing.** ``call_tool`` takes a qualified name and finds the upstream and the
real tool name. The upstream half is always exact. The tool half is exact too
unless the name had to be truncated, and truncation cannot be reversed — so
those are resolved through the upstream's own catalogue.

The resolution map is a *memo*, not session state: it is rebuilt from upstreams
on demand, so a cold instance behaves identically to a warm one. That is what
keeps this compatible with the stateless model of ADR 0001.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import anyio

from acp.exceptions import ACPError, UnknownToolError, UnknownUpstreamError
from acp.gateway.naming import (
    may_be_truncated,
    qualify,
    suffix_of,
    upstream_of,
)
from acp.upstream import CallToolResult, ToolDefinition, Upstream


@dataclass(frozen=True, slots=True)
class Catalogue:
    """The merged tool catalogue, plus whatever went wrong producing it."""

    tools: list[ToolDefinition]
    failures: dict[str, ACPError] = field(default_factory=dict)
    """Upstream name to the error it raised. Empty when every upstream answered."""

    @property
    def is_total_failure(self) -> bool:
        """True when nothing answered — no tools *and* at least one failure.

        Distinguishes "every upstream is down" from the legitimate case of
        upstreams that simply expose no tools, which are not the same thing and
        deserve different responses.
        """
        return not self.tools and bool(self.failures)


class UpstreamRegistry:
    """Holds the configured upstreams and brokers between them."""

    def __init__(self, clients: Iterable[Upstream]) -> None:
        self._clients: dict[str, Upstream] = {c.config.name: c for c in clients}
        # qualified name -> real tool name, populated as catalogues are read.
        # Only ever consulted for names that may have been truncated.
        self._resolved: dict[str, str] = {}

    @property
    def names(self) -> list[str]:
        return sorted(self._clients)

    # -- catalogue ---------------------------------------------------------

    async def list_tools(self) -> Catalogue:
        """Fetch and merge every upstream's catalogue, concurrently.

        Concurrent rather than sequential because latency here is the sum of
        round trips otherwise, and an agent waits for this before it can do
        anything at all.
        """
        tools: dict[str, list[ToolDefinition]] = {}
        failures: dict[str, ACPError] = {}

        async def fetch(name: str, client: Upstream) -> None:
            try:
                tools[name] = await client.list_tools()
            except ACPError as exc:
                # Deliberately caught, not propagated: one bad upstream must not
                # take down the catalogue. The caller sees it in `failures`.
                failures[name] = exc

        async with anyio.create_task_group() as group:
            for name, client in self._clients.items():
                group.start_soon(fetch, name, client)

        merged: list[ToolDefinition] = []
        for name in sorted(tools):
            for tool in tools[name]:
                qualified = qualify(name, tool.name)
                self._resolved[qualified] = tool.name
                merged.append(tool.model_copy(update={"name": qualified}))

        return Catalogue(tools=merged, failures=failures)

    # -- routing -----------------------------------------------------------

    async def call_tool(
        self, qualified: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Route a qualified tool call to the upstream that owns it."""
        upstream = upstream_of(qualified)
        client = self._clients.get(upstream)
        if client is None:
            raise UnknownUpstreamError(
                f"no upstream named {upstream!r} is configured",
                upstream=upstream,
                details={"tool": qualified, "configured": self.names},
            )

        tool = await self._resolve(qualified, client)
        return await client.call_tool(tool, arguments)

    async def _resolve(self, qualified: str, client: Upstream) -> str:
        """Find the upstream's real name for a qualified tool.

        The fast path is the common one and costs nothing: a name shorter than
        the length limit cannot have been truncated, so its suffix *is* the real
        name. See ``naming.may_be_truncated`` for why that is sound in one
        direction only.

        Ambiguous names are resolved from the memo, and on a miss by re-reading
        that one upstream's catalogue. Guessing is not an option here — a wrong
        guess invokes a different tool than the caller asked for, which for a
        non-idempotent tool is unrecoverable.
        """
        if not may_be_truncated(qualified):
            return suffix_of(qualified)

        known = self._resolved.get(qualified)
        if known is not None:
            return known

        # Cold or stale memo: rebuild this upstream's entries and try once more.
        for tool in await client.list_tools():
            self._resolved[qualify(client.config.name, tool.name)] = tool.name

        known = self._resolved.get(qualified)
        if known is None:
            raise UnknownToolError(
                f"{client.config.name} exposes no tool matching {qualified!r}",
                upstream=client.config.name,
                details={"tool": qualified},
            )
        return known
