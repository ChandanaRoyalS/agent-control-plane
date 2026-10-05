"""Background upstream health probing, and withdrawing unhealthy upstreams' tools.

The prober lets open breakers recover without live traffic, and withdrawal shows
agents an outage in the tool list. A probe is a real `tools/list` through the whole
stack. Never-probed upstreams count as available: this is availability, so it fails
open. Top-level so the admin app need not import the MCP SDK.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

import anyio

from acp.exceptions import ACPError, UpstreamCircuitOpenError
from acp.upstream import ListToolsResult, Upstream

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL = 15.0
DEFAULT_JITTER = 0.3

HealthObserver = Callable[["HealthRecord", "UpstreamHealth"], object]
"""Called on health transitions only, with the new record and the previous state.

Used by the trace console. Health changes are not audited, since no call was
decided; the console marks them `observed` (ADR 0056).
"""

CatalogueObserver = Callable[[str, ListToolsResult], object]
"""Sees each catalogue the prober fetches (used by drift detection); return ignored."""


class UpstreamHealth(StrEnum):
    """What the last probe concluded."""

    UNKNOWN = "unknown"
    """Never probed, or probing is disabled. Treated as available."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True, slots=True)
class HealthRecord:
    """One upstream's last known state."""

    upstream: str
    state: UpstreamHealth = UpstreamHealth.UNKNOWN
    checked_at: float | None = None
    error: str | None = None
    tool_count: int | None = None

    @property
    def serves_tools(self) -> bool:
        """Whether this upstream's tools belong in the catalogue; only ``UNHEALTHY`` is no."""
        return self.state is not UpstreamHealth.UNHEALTHY

    def as_dict(self) -> dict[str, object]:
        """For the readiness endpoint; carries the error type, never its message."""
        return {
            "upstream": self.upstream,
            "state": str(self.state),
            "checked_at": self.checked_at,
            "error": self.error,
            "tools": self.tool_count,
        }


class HealthMonitor:
    """Probes every upstream on an interval and remembers what it found."""

    def __init__(
        self,
        upstreams: Sequence[Upstream],
        *,
        interval: float = DEFAULT_INTERVAL,
        jitter: float = DEFAULT_JITTER,
        clock: Callable[[], float] | None = None,
        uniform: Callable[[float, float], float] | None = None,
        on_catalogue: CatalogueObserver | None = None,
        on_health: HealthObserver | None = None,
    ) -> None:
        self._upstreams = list(upstreams)
        self._interval = interval
        self._jitter = jitter
        self._clock = clock or time.monotonic
        self._uniform = uniform or random.uniform
        self._on_catalogue = on_catalogue
        self._on_health = on_health
        self._records: dict[str, HealthRecord] = {
            u.config.name: HealthRecord(u.config.name) for u in self._upstreams
        }

    # -- reading -----------------------------------------------------------

    def record_for(self, upstream: str) -> HealthRecord:
        """This upstream's last known state. Unknown for a name never seen."""
        return self._records.get(upstream, HealthRecord(upstream))

    def snapshot(self) -> Mapping[str, HealthRecord]:
        """A copy, so a reader cannot observe a probe half-applied."""
        return dict(self._records)

    def serves_tools(self, upstream: str) -> bool:
        return self.record_for(upstream).serves_tools

    def withdrawn(self) -> Mapping[str, str]:
        """Upstreams currently withheld from the catalogue, and why."""
        return {
            name: record.error or "unhealthy"
            for name, record in self._records.items()
            if not record.serves_tools
        }

    @property
    def is_serving_nothing(self) -> bool:
        """True when upstreams are configured and none can serve; False with none configured."""
        return bool(self._records) and not any(r.serves_tools for r in self._records.values())

    # -- probing -----------------------------------------------------------

    async def probe_once(self) -> None:
        """Probe every upstream concurrently, so one slow upstream delays no other."""
        async with anyio.create_task_group() as tg:
            for upstream in self._upstreams:
                tg.start_soon(self._probe, upstream)

    async def _probe(self, upstream: Upstream) -> None:
        name = upstream.config.name
        record = self._records[name]
        previous = record.state
        try:
            # Bypass the cache so the probe is live; it also re-warms the cache.
            await upstream.invalidate()
            result = await upstream.list_tools()
        except UpstreamCircuitOpenError:
            # Our own refusal, not news about the upstream: keep the original error
            # so /readyz still shows the real cause.
            self._update(
                name,
                UpstreamHealth.UNHEALTHY,
                error=record.error or "UpstreamCircuitOpenError",
                previous=previous,
            )
        except ACPError as exc:
            self._update(
                name,
                UpstreamHealth.UNHEALTHY,
                error=type(exc).__name__,
                previous=previous,
            )
        except Exception as exc:
            # A gateway bug, but caught so the prober survives for other upstreams.
            logger.exception("health.probe_failed", extra={"upstream": name})
            self._update(
                name, UpstreamHealth.UNHEALTHY, error=type(exc).__name__, previous=previous
            )
        else:
            self._update(
                name, UpstreamHealth.HEALTHY, tool_count=len(result.tools), previous=previous
            )
            self._offer(name, result)

    def _offer(self, name: str, result: ListToolsResult) -> None:
        """Pass a fetched catalogue to the observer; its exceptions are logged, not raised."""
        if self._on_catalogue is None:
            return
        try:
            self._on_catalogue(name, result)
        except Exception:
            logger.exception("health.observer_failed", extra={"upstream": name})

    def _update(
        self,
        name: str,
        state: UpstreamHealth,
        *,
        previous: UpstreamHealth,
        error: str | None = None,
        tool_count: int | None = None,
    ) -> None:
        self._records[name] = HealthRecord(
            upstream=name,
            state=state,
            checked_at=self._clock(),
            error=error,
            tool_count=tool_count,
        )
        if state is not previous:
            # Log transitions only, not every probe.
            logger.warning(
                "health.changed",
                extra={
                    "upstream": name,
                    "state": str(state),
                    "previous": str(previous),
                    "error": error,
                    "tools": tool_count,
                },
            )
            self._notify(self._records[name], previous)

    def _notify(self, record: HealthRecord, previous: UpstreamHealth) -> None:
        """Tell the health observer; its exceptions are logged so they cannot stop probing."""
        if self._on_health is None:
            return
        try:
            self._on_health(record, previous)
        except Exception:
            logger.exception("health.observer_failed", extra={"upstream": record.upstream})

    # -- the loop ----------------------------------------------------------

    async def run(self, *, sleep: Callable[[float], object] | None = None) -> None:
        """Probe immediately, then forever on a jittered interval, until cancelled."""
        rest = sleep or anyio.sleep
        while True:
            await self.probe_once()
            await rest(self._next_delay())  # type: ignore[misc]

    def _next_delay(self) -> float:
        """The interval, jittered so replicas do not probe in synchronised bursts."""
        spread = self._interval * self._jitter
        return max(0.0, self._uniform(self._interval - spread, self._interval + spread))


def upstream_names(upstreams: Iterable[Upstream]) -> list[str]:
    """Convenience for logging and for the readiness payload's ordering."""
    return [u.config.name for u in upstreams]
