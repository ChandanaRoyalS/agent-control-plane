"""Caching an upstream's catalogue, for exactly as long as it says to.

The obvious benefit is the small one: a `tools/list` served from memory instead
of a round trip, once per upstream rather than once per agent request.

The benefit that actually matters is one layer further out. An agent's prompt
contains its tool list. If that list changes — even in field ordering — the
model provider's prompt cache misses, and the whole prompt is billed and
processed at full price again. A catalogue that is stable for five minutes is
not merely a latency improvement; it is the difference between paying for those
tokens once and paying for them on every single turn. Cache stability here is a
cost decision that happens to look like a performance one.

**The upstream decides, within limits we set.** ``ttlMs`` and ``cacheScope``
come from the upstream, and both default to the conservative answer — zero and
``private`` — so caching is opted into rather than assumed. But a hint is input
from a system the gateway does not control, so it is clamped: an upstream
advertising a day-long TTL, by bug or by design, would otherwise freeze its
catalogue for a day and the gateway would keep serving tools that no longer
exist.

**``private`` is an authorization boundary, not a performance hint.** The MCP
SDK's own client cache states the rule plainly: only ``public`` entries may be
shared across authorization contexts. A ``private`` catalogue is one the
upstream computed *for a particular caller*, and holding it in a cache shared
between callers would hand one principal the tool list belonging to another.
This gateway has no principals yet — identity arrives in task 22 — so there is
exactly one thing it can do safely, and it does that: cache ``public`` only.
When identity lands, the cache key gains the principal and ``private`` becomes
cacheable per-principal rather than not at all.

**No stale-on-error.** Serving a cached catalogue for an upstream that has since
died would have the agent calling tools that cannot work — precisely what
task 18's withdrawal exists to prevent. A cache entry is a claim about
freshness, not a consolation prize.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self

from acp.upstream.config import UpstreamConfig
from acp.upstream.models import CallToolResult, ListToolsResult
from acp.upstream.protocol import Upstream

logger = logging.getLogger(__name__)

MAX_TTL_MS = 24 * 60 * 60 * 1000
"""Twenty-four hours, matching the ceiling the MCP SDK's own client applies.

Pinned to the SDK's value by a conformance test rather than chosen
independently: two caches in one system disagreeing about the maximum lifetime
of the same response is a difference nobody would find until it mattered.
"""


@dataclass(frozen=True, slots=True)
class CachePolicy:
    """What this gateway will and will not do with an upstream's hint."""

    enabled: bool = True

    max_ttl_ms: int = MAX_TTL_MS
    """Ceiling applied to whatever the upstream asked for."""

    default_ttl_ms: int = 0
    """Used when a response carries no hint at all.

    Zero — do not cache — matching the SDK's default. An upstream that says
    nothing has not agreed to anything, and inferring consent from silence is
    how a gateway ends up serving a catalogue its owner never sanctioned.
    """

    def ttl_seconds_for(self, result: ListToolsResult) -> float:
        """How long this response may be held, in seconds. Zero means not at all.

        Returns zero for anything ``private``, which is the authorization rule
        rather than a tuning choice — see the module docstring.
        """
        if not self.enabled or result.cache_scope != "public":
            return 0.0
        # An explicit `ttlMs: 0` is an instruction, not an absence — the SDK's
        # own cache makes the same distinction, in its words "an explicit
        # ttlMs: 0 stays 0". Letting a configured default override it would
        # mean caching a catalogue whose owner said, in as many words, not to.
        # Pydantic's `model_fields_set` is what tells the two apart.
        ttl_ms = result.ttl_ms if "ttl_ms" in result.model_fields_set else self.default_ttl_ms
        return min(ttl_ms, self.max_ttl_ms) / 1000.0


@dataclass(frozen=True, slots=True)
class CacheEntry:
    result: ListToolsResult
    expires_at: float


def policy_for(config: UpstreamConfig) -> CachePolicy:
    return CachePolicy(
        enabled=config.cache_enabled,
        max_ttl_ms=config.max_cache_ttl_ms,
        default_ttl_ms=config.default_cache_ttl_ms,
    )


class CachingUpstreamClient:
    """Holds one upstream's catalogue for as long as that upstream permits.

    Outermost in the stack (see ``acp.upstream.factory``), so a hit costs
    nothing at all — no retry bookkeeping, no breaker check, no bulkhead slot.
    A cached answer is one the gateway already has; making it walk through three
    layers of failure handling to be handed back would be theatre.

    Only ``tools/list`` is cached. A tool *call* is an action with effects, and
    a cache that returned yesterday's answer to `create_ticket` would be a bug
    with consequences rather than a stale read. Result caching for genuinely
    idempotent tools is task 43, and it needs the per-principal key this layer
    deliberately does not have yet.
    """

    def __init__(
        self,
        inner: Upstream,
        policy: CachePolicy | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._inner = inner
        self._policy = policy or policy_for(inner.config)
        self._clock = clock or time.monotonic
        self._entry: CacheEntry | None = None

    @property
    def config(self) -> UpstreamConfig:
        return self._inner.config

    @property
    def cached_until(self) -> float | None:
        """When the held entry expires, or ``None`` when nothing is held.

        Exposed for the readiness payload and for tests; a cache whose state
        cannot be observed is one whose behaviour has to be inferred from
        timing.
        """
        return self._entry.expires_at if self._entry else None

    # -- lifecycle ---------------------------------------------------------

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- operations --------------------------------------------------------

    async def list_tools(self) -> ListToolsResult:
        entry = self._entry
        if entry is not None and self._clock() < entry.expires_at:
            return entry.result

        # Deliberately dropped *before* the fetch rather than after it. If the
        # fetch raises, the expired entry must not survive to be served later —
        # an upstream that has started failing is exactly the one whose old
        # catalogue is least trustworthy.
        self._entry = None
        result = await self._inner.list_tools()
        self._store(result)
        return result

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Never cached. A tool call is an action, not a lookup."""
        return await self._inner.call_tool(name, arguments)

    async def invalidate(self) -> None:
        """Forget the entry, and tell the layers below to do the same.

        Called by the health monitor before every probe. A probe served from
        cache would report on a conversation that happened minutes ago, which is
        the one thing a liveness check must never do.
        """
        self._entry = None
        await self._inner.invalidate()

    # -- internals ---------------------------------------------------------

    def _store(self, result: ListToolsResult) -> None:
        ttl = self._policy.ttl_seconds_for(result)
        if ttl <= 0:
            return
        self._entry = CacheEntry(result=result, expires_at=self._clock() + ttl)
        logger.debug(
            "catalogue.cached",
            extra={
                "upstream": self.config.name,
                "ttl_seconds": round(ttl, 3),
                "tools": len(result.tools),
                "requested_ttl_ms": result.ttl_ms,
            },
        )
