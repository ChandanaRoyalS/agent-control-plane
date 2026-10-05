"""Caching an upstream's catalogue, for exactly as long as it says to (ADR 0012).

A stable catalogue also keeps the model provider's prompt cache warm. The
upstream's ``ttlMs`` hint is clamped. The cache is keyed per upstream, so only
``public`` catalogues are held: ``private`` is an authorization boundary
(per-principal result caching is ``acp.results``, ADR 0035). No stale-on-error, so a
dead upstream's tools are not served (ADR 0011).
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
"""Twenty-four hours, pinned to the MCP SDK client's ceiling by a conformance test."""


@dataclass(frozen=True, slots=True)
class CachePolicy:
    """What this gateway will and will not do with an upstream's hint."""

    enabled: bool = True

    max_ttl_ms: int = MAX_TTL_MS
    """Ceiling applied to whatever the upstream asked for."""

    default_ttl_ms: int = 0
    """Used when a response carries no hint; zero (do not cache), as in the SDK."""

    def ttl_seconds_for(self, result: ListToolsResult) -> float:
        """Seconds this response may be held; zero for disabled or ``private``."""
        if not self.enabled or result.cache_scope != "public":
            return 0.0
        # An explicit `ttlMs: 0` stays 0, as in the SDK; the default applies only
        # when the field is absent (`model_fields_set`).
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

    Outermost in the stack, so a hit skips every other layer. Only ``tools/list``
    is cached; result caching needs a per-principal key and lives in
    `acp.results.cache`.
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
        """When the held entry expires, or ``None`` when nothing is held."""
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

        # Dropped before the fetch, so a failed fetch leaves no stale entry.
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
        """Forget the entry here and below; the health monitor calls it before each probe."""
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
