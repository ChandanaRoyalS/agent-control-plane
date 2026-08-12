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
from acp.health import HealthMonitor
from acp.upstream import CallToolResult, ListToolsResult, ToolDefinition, Upstream


@dataclass(frozen=True, slots=True)
class Catalogue:
    """The merged tool catalogue, plus whatever went wrong producing it."""

    tools: list[ToolDefinition]
    failures: dict[str, ACPError] = field(default_factory=dict)
    """Upstream name to the error it raised. Empty when every upstream answered."""

    ttl_ms: int = 0
    """How long an agent may cache *this* merged catalogue.

    The minimum of the contributing upstreams' TTLs: a merged answer is only as
    durable as its least durable part. Zero whenever anything failed or was
    withdrawn, because the thing most likely to change in the next minute is
    precisely the upstream that is currently broken.
    """

    cache_scope: str = "private"
    """``public`` only when every contributing upstream said ``public``.

    One private component makes the whole merge private. Scope is an
    authorization boundary, not a performance dial, and it does not average.
    """

    withdrawn: dict[str, str] = field(default_factory=dict)
    """Upstreams not even attempted, because health probing found them down.

    Kept apart from ``failures`` because they are a different kind of event. A
    failure is a surprise worth a warning on the request that hit it; a
    withdrawal is a known condition already logged once when it started. Merging
    them would mean an upstream that has been down for an hour logs a warning on
    every single request for that hour.
    """

    @property
    def is_total_failure(self) -> bool:
        """True when nothing answered — no tools, and something went wrong.

        Distinguishes "every upstream is down" from the legitimate case of
        upstreams that simply expose no tools, which are not the same thing and
        deserve different responses. A withdrawal counts: an agent given an
        empty catalogue would conclude it has no tools and proceed without
        them, which is exactly the outcome the total-failure error prevents.
        """
        return not self.tools and bool(self.failures or self.withdrawn)


def _compose_hints(results: Iterable[ListToolsResult], *, degraded: bool) -> tuple[int, str]:
    """Combine several upstreams' freshness hints into one for the merge.

    Conservative in both directions, and deliberately so. The TTL is the
    *minimum*, because a merged catalogue stops being accurate the moment its
    shortest-lived component does. The scope is ``public`` only if every
    contributor said ``public``, because one private component makes the whole
    answer caller-specific — scope is a boundary, and boundaries do not average.

    A degraded catalogue is not cacheable at all. The upstream most likely to
    change in the next minute is the one that is currently broken, and freezing
    a reduced tool list into an agent's prompt is how a recovered upstream stays
    invisible long after it came back.
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
        # Optional on purpose. Without a monitor every upstream is attempted,
        # which is exactly the behaviour before task 18 — so a registry built
        # by a test, or by `build_app` directly, is unaffected.
        self._health = health
        # qualified name -> real tool name, populated as catalogues are read.
        # Only ever consulted for names that may have been truncated.
        self._resolved: dict[str, str] = {}

    @property
    def names(self) -> list[str]:
        return sorted(self._clients)

    @property
    def known_tools(self) -> frozenset[str]:
        """Every qualified tool name this process has resolved so far.

        The firewall's tool-mention detector needs a catalogue to compare a
        document against, and this is the cheap answer: no fan-out, no upstream
        call, just what has already been seen. It is what makes that detector
        the one only a gateway can write — a document returned by ``mock-a``
        naming ``mock-b__delete_record`` has read this estate's catalogue.

        Honestly incomplete, and incomplete in the safe direction. A process
        that has never served a ``tools/list`` knows nothing, so the detector
        under-reports rather than inventing names — which is the same choice
        ADR 0036 made for the screener's defaults. In practice an agent must
        list before it can call, so by the first ``tools/call`` this is
        populated.
        """
        return frozenset(self._resolved)

    # -- catalogue ---------------------------------------------------------

    async def list_tools(self) -> Catalogue:
        """Fetch and merge every upstream's catalogue, concurrently.

        Concurrent rather than sequential because latency here is the sum of
        round trips otherwise, and an agent waits for this before it can do
        anything at all.
        """
        results: dict[str, ListToolsResult] = {}
        failures: dict[str, ACPError] = {}
        withdrawn: dict[str, str] = {}

        async def fetch(name: str, client: Upstream) -> None:
            try:
                results[name] = await client.list_tools()
            except ACPError as exc:
                # Deliberately caught, not propagated: one bad upstream must not
                # take down the catalogue. The caller sees it in `failures`.
                failures[name] = exc

        async with anyio.create_task_group() as group:
            for name, client in self._clients.items():
                if self._health is not None and not self._health.serves_tools(name):
                    # Known down. Not attempted at all — the breaker would make
                    # the attempt cheap, but "cheap" is not "free", and an agent
                    # is waiting on this fan-out.
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
