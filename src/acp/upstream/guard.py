"""Bulkhead and breaker, wrapped around one upstream.

The bulkhead caps concurrent calls per upstream so one slow upstream cannot take
all capacity; the call over the cap is refused immediately, never queued. The
breaker is checked before a slot is taken, so an open circuit fails fast. Retry
sits outside this layer (see ``acp.upstream.factory``).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any, Self, TypeVar

import anyio

from acp.exceptions import UpstreamOverloadedError
from acp.observability import metrics
from acp.upstream.breaker import BreakerSnapshot, CircuitBreaker
from acp.upstream.config import UpstreamConfig
from acp.upstream.models import CallToolResult, ListToolsResult
from acp.upstream.protocol import Upstream

logger = logging.getLogger(__name__)

T = TypeVar("T")


class Bulkhead:
    """A hard ceiling on concurrent calls to one upstream.

    Bounds calls without waiting, unlike the HTTP pool limit. Config keeps it at
    or below the pool size, so a pool timeout signals a real fault.
    """

    def __init__(self, upstream: str, capacity: int) -> None:
        self._upstream = upstream
        self._capacity = capacity
        self._semaphore = anyio.Semaphore(capacity)

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def in_flight(self) -> int:
        """Calls currently holding a slot. For metrics and health reporting."""
        return self._capacity - self._semaphore.value

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Hold a slot for the duration of one call, or refuse it now."""
        try:
            self._semaphore.acquire_nowait()
        except anyio.WouldBlock as exc:
            # WARNING: a burst is the earliest sign an upstream is slowing.
            logger.warning(
                "upstream.overloaded",
                extra={"upstream": self._upstream, "capacity": self._capacity},
            )
            raise UpstreamOverloadedError(
                f"{self._upstream} already has {self._capacity} calls in flight",
                upstream=self._upstream,
                details={"capacity": self._capacity},
            ) from exc
        self._publish()
        try:
            yield
        finally:
            # In `finally` so a cancelled call cannot leak the slot permanently.
            self._semaphore.release()
            self._publish()

    def _publish(self) -> None:
        metrics.observe_bulkhead(
            upstream=self._upstream, in_flight=self.in_flight, capacity=self._capacity
        )


class GuardedUpstreamClient:
    """An upstream that refuses calls its breaker or bulkhead should not allow."""

    def __init__(
        self,
        inner: Upstream,
        breaker: CircuitBreaker | None = None,
        bulkhead: Bulkhead | None = None,
    ) -> None:
        self._inner = inner
        self._breaker = breaker or CircuitBreaker(inner.config.name)
        self._bulkhead = bulkhead or Bulkhead(inner.config.name, inner.config.max_concurrency)

    @property
    def config(self) -> UpstreamConfig:
        return self._inner.config

    @property
    def breaker(self) -> CircuitBreaker:
        """For `acp.health`, which withdraws an upstream while its circuit is open."""
        return self._breaker

    @property
    def bulkhead(self) -> Bulkhead:
        return self._bulkhead

    def snapshot(self) -> BreakerSnapshot:
        return self._breaker.snapshot()

    # -- lifecycle ---------------------------------------------------------

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def invalidate(self) -> None:
        """Not guarded: it makes no network call, and must work during recovery."""
        await self._inner.invalidate()

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
        return await self._guarded(self._inner.list_tools)

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        async def operation() -> CallToolResult:
            return await self._inner.call_tool(name, arguments)

        return await self._guarded(operation)

    async def _guarded(self, operation: Callable[[], Awaitable[T]]) -> T:
        async with self._breaker.guard(), self._bulkhead.slot():
            return await operation()
