"""Bulkhead and breaker, wrapped around one upstream.

The bulkhead is the older of the two ideas and the less discussed. A ship's hull
is divided into compartments so that a breach floods one and the ship stays up.
The failure it prevents here is the one where a single slow upstream consumes
everything: every request to it holds a worker for the full read timeout, those
requests pile up because agents keep asking, and eventually the gateway has no
capacity left for the four upstreams that are working perfectly. The gateway
does not fall over because it broke — it falls over because it was too patient
with something that did.

So each upstream gets a fixed number of concurrent in-flight calls, and the
(N+1)th is refused *immediately* rather than queued. Queueing is the tempting
alternative and it is the wrong one: a queue converts saturation into latency,
and latency is precisely what the caller cannot distinguish from the upstream
being slow. Refusing says something true and says it in a millisecond.

**Ordering.** The breaker is checked first, then the bulkhead slot is taken.
Both orderings are defensible; this one is chosen so that fast-failing an open
circuit never has to wait for capacity — the cheapest possible answer should not
queue behind the most expensive one.

The whole stack, outermost to innermost:

    RetryingUpstreamClient   → decides whether to try again, and sleeps
      GuardedUpstreamClient  → decides whether to try at all
        UpstreamClient       → one call in, one HTTP request out

Retry sits outside the bulkhead so a retry's backoff sleep does not occupy a
slot it is not using, and outside the breaker so the breaker counts *attempts*
rather than logical calls — three retries of one failing call are three pieces
of evidence that the upstream is down, not one.
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
from acp.upstream.models import CallToolResult, ToolDefinition
from acp.upstream.protocol import Upstream

logger = logging.getLogger(__name__)

T = TypeVar("T")


class Bulkhead:
    """A hard ceiling on concurrent calls to one upstream.

    Distinct from the connection-pool limit already on the HTTP client, which
    bounds *sockets* and, on reaching the limit, waits for ``pool_timeout``.
    This bounds *calls* and does not wait. Configuration keeps the bulkhead at
    or below the pool size (see ``UpstreamConfig``), which has a useful
    consequence: the pool can then never be the thing that saturates, so a pool
    timeout in production stops being routine backpressure and becomes a signal
    that something is genuinely wrong.
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
            # At WARNING, not INFO: refusing a call is a real event with a real
            # consequence for the agent, and a burst of these is the earliest
            # signal that an upstream has started to slow down.
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
            # In a `finally`, so a cancelled or failing call cannot leak the
            # slot. A leaked slot is permanent: capacity only ever goes down.
            self._semaphore.release()
            self._publish()

    def _publish(self) -> None:
        metrics.observe_bulkhead(
            upstream=self._upstream, in_flight=self.in_flight, capacity=self._capacity
        )


class GuardedUpstreamClient:
    """An upstream that refuses calls it should not make.

    Wraps any :class:`~acp.upstream.protocol.Upstream`, so it composes with the
    retry wrapper in either order — though the stack described in this module's
    docstring is the one the factory builds, and the reasons are given there.
    """

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
        """Exposed for the health endpoint in task 18, which withdraws an
        upstream from the catalogue while its circuit is open."""
        return self._breaker

    @property
    def bulkhead(self) -> Bulkhead:
        return self._bulkhead

    def snapshot(self) -> BreakerSnapshot:
        return self._breaker.snapshot()

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

    async def list_tools(self) -> list[ToolDefinition]:
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
