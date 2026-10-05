"""The upstreams the gateway brokers for: catalogue merging and call routing.

``list_tools`` fans out concurrently and merges under qualified names (ADR 0003); one
upstream failing does not fail the catalogue. ``call_tool`` routes exactly, resolving
possibly truncated names via the upstream's catalogue. The resolution map is a memo
rebuilt on demand, keeping the stateless model of ADR 0001.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import anyio

from acp.exceptions import ACPError, UnknownToolError, UnknownUpstreamError
from acp.gateway.naming import (
    MalformedToolNameError,
    may_be_truncated,
    qualify,
    suffix_of,
    upstream_of,
)
from acp.health import HealthMonitor
from acp.upstream import CallToolResult, ListToolsResult, ToolDefinition, Upstream


@dataclass(frozen=True, slots=True)
class Catalogue:
    """The merged tool catalogue, plus whatever went wrong producing it."""

    tools: list[ToolDefinition]
    failures: dict[str, ACPError] = field(default_factory=dict)
    """Upstream name to the error it raised. Empty when every upstream answered."""

    ttl_ms: int = 0
    """Milliseconds an agent may cache this catalogue; see ``_compose_hints``."""

    cache_scope: str = "private"
    """``public`` only when every contributing upstream said ``public``."""

    withdrawn: dict[str, str] = field(default_factory=dict)
    """Upstreams skipped because health probing found them down.

    Separate from ``failures`` so a known outage is not re-warned on every request.
    """

    @property
    def is_total_failure(self) -> bool:
        """Return True when there are no tools and something failed or was withdrawn.

        Distinguishes an outage from upstreams that expose no tools.
        """
        return not self.tools and bool(self.failures or self.withdrawn)


def _compose_hints(results: Iterable[ListToolsResult], *, degraded: bool) -> tuple[int, str]:
    """Combine upstream freshness hints: minimum TTL, ``public`` only if all are.

    A degraded catalogue is not cacheable, so a recovered upstream reappears promptly.
    """
    collected = list(results)
    if degraded or not collected:
        return 0, "private"
    if any(r.cache_scope != "public" or r.ttl_ms <= 0 for r in collected):
        return 0, "private"
    return min(r.ttl_ms for r in collected), "public"


class UpstreamRegistry:
    """Holds the configured upstreams and brokers between them."""

    def __init__(self, clients: Iterable[Upstream], health: HealthMonitor | None = None) -> None:
        self._clients: dict[str, Upstream] = {c.config.name: c for c in clients}
        # Optional: without a monitor every upstream is attempted.
        self._health = health
        # qualified name -> real tool name; consulted only for possibly truncated names.
        self._resolved: dict[str, str] = {}

    @property
    def names(self) -> list[str]:
        return sorted(self._clients)

    @property
    def known_tools(self) -> frozenset[str]:
        """Return every qualified tool name this process has resolved so far.

        Feeds the firewall's tool-mention detector without a fan-out. Incomplete in the
        safe direction (under-reports before the first ``tools/list``), as in ADR 0036.
        """
        return frozenset(self._resolved)

    # -- catalogue ---------------------------------------------------------

    async def list_tools(self) -> Catalogue:
        """Fetch and merge every upstream's catalogue concurrently."""
        results: dict[str, ListToolsResult] = {}
        failures: dict[str, ACPError] = {}
        withdrawn: dict[str, str] = {}

        async def fetch(name: str, client: Upstream) -> None:
            try:
                results[name] = await client.list_tools()
            except ACPError as exc:
                # One bad upstream must not fail the catalogue; reported in `failures`.
                failures[name] = exc

        async with anyio.create_task_group() as group:
            for name, client in self._clients.items():
                if self._health is not None and not self._health.serves_tools(name):
                    # Known down: skip it so the agent does not wait on it.
                    withdrawn[name] = self._health.record_for(name).error or "unhealthy"
                    continue
                group.start_soon(fetch, name, client)

        merged: list[ToolDefinition] = []
        for name in sorted(results):
            for tool in results[name].tools:
                qualified = qualify(name, tool.name)
                self._resolved[qualified] = tool.name
                merged.append(tool.model_copy(update={"name": qualified}))

        ttl_ms, scope = _compose_hints(results.values(), degraded=bool(failures or withdrawn))
        return Catalogue(
            tools=merged,
            failures=failures,
            withdrawn=withdrawn,
            ttl_ms=ttl_ms,
            cache_scope=scope,
        )

    # -- routing -----------------------------------------------------------

    async def call_tool(
        self, qualified: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Route a qualified tool call to the upstream that owns it.

        Raises:
            UnknownToolError: Name has no separator (caller input, audited by the server's
                `ACPError` path; W11 of the external review) or matches no tool.
            UnknownUpstreamError: No such upstream is configured.
        """
        try:
            upstream = upstream_of(qualified)
        except MalformedToolNameError as exc:
            raise UnknownToolError(
                f"tool name {qualified!r} is not qualified with an upstream",
                upstream="",
                details={"tool": qualified},
            ) from exc
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
        """Return the upstream's real name for a qualified tool.

        Names below the limit are exact (``naming.may_be_truncated``). Others come from the
        memo, refreshed once from this upstream on a miss; never guessed.
        """
        if not may_be_truncated(qualified):
            return suffix_of(qualified)

        known = self._resolved.get(qualified)
        if known is not None:
            return known

        # Cold or stale memo: rebuild this upstream's entries and try once more.
        for tool in (await client.list_tools()).tools:
            self._resolved[qualify(client.config.name, tool.name)] = tool.name

        known = self._resolved.get(qualified)
        if known is None:
            raise UnknownToolError(
                f"{client.config.name} exposes no tool matching {qualified!r}",
                upstream=client.config.name,
                details={"tool": qualified},
            )
        return known
