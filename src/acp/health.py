"""Background health probing, and withdrawing what is not answering.

Top-level rather than inside ``acp.gateway`` on purpose. Health is a property of
*upstreams*, and the admin listener needs to report it — putting it under
``acp.gateway`` made the metrics-and-readiness app import the inbound server and
therefore the MCP SDK, which is a dependency it has no reason to carry.

The breaker (task 14) already knows when an upstream is failing. Two things it
cannot do on its own, and this module exists for both.

**It cannot recover without traffic.** A breaker opens, waits out its reset
timeout, and then needs *somebody* to make a call before it will half-open and
find out whether the upstream came back. With no traffic there is nobody, so a
gateway that goes quiet overnight wakes up with every circuit still open until
the first agent of the morning pays a connect timeout to discover otherwise.
A background prober is that somebody, and it means the cost of finding out is
paid by a scheduled task rather than by whichever request happened to be next.

**It cannot tell an agent anything.** Its knowledge reaches the logs and the
metrics, which is to say it reaches operators. The agent still asks for the full
catalogue and still gets a partial one with no explanation. Withdrawing an
unhealthy upstream's tools makes the breaker's knowledge visible in the only
place the agent actually looks — the tool list. An agent that never sees
`mock-a__search` will not call it, and will plan around its absence, which is a
far better outcome than calling it and handling an error.

**Probing means calling `tools/list`.** MCP has no health method, and inventing
one would be worse anyway: a synthetic ping can succeed while the operation the
gateway actually needs is broken. The probe is the real request, through the
whole stack, so the breaker sees its result as evidence like any other.

**Unknown means ask.** An upstream that has never been probed is not withdrawn.
Withdrawing on ignorance would turn a monitor that failed to start into a
gateway that serves nothing — a monitoring bug escalated into an outage. The
security posture elsewhere in this project is deny-by-default; this is
availability, and it fails the other way on purpose.
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
from acp.upstream import Upstream

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL = 15.0
DEFAULT_JITTER = 0.3


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
        """Whether this upstream's tools belong in the merged catalogue.

        ``UNKNOWN`` counts as yes — see the module docstring. The only state
        that withdraws anything is a probe that actually failed.
        """
        return self.state is not UpstreamHealth.UNHEALTHY

    def as_dict(self) -> dict[str, object]:
        """For the readiness endpoint. Deliberately no exception message: the
        error *type* is reportable, its text is not."""
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
    ) -> None:
        self._upstreams = list(upstreams)
        self._interval = interval
        self._jitter = jitter
        self._clock = clock or time.monotonic
        self._uniform = uniform or random.uniform
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
        """True when upstreams are configured and none of them can serve.

        Distinct from "no upstreams configured", which is a legitimate way to
        run this gateway and must not read as an outage.
        """
        return bool(self._records) and not any(r.serves_tools for r in self._records.values())

    # -- probing -----------------------------------------------------------

    async def probe_once(self) -> None:
        """Probe every upstream concurrently.

        Concurrently rather than in sequence for the same reason the catalogue
        fan-out is: one unreachable upstream taking its full connect timeout
        must not delay finding out about the others.
        """
        async with anyio.create_task_group() as tg:
            for upstream in self._upstreams:
                tg.start_soon(self._probe, upstream)

    async def _probe(self, upstream: Upstream) -> None:
        name = upstream.config.name
        record = self._records[name]
        previous = record.state
        try:
            tools = await upstream.list_tools()
        except UpstreamCircuitOpenError:
            # The gateway's own refusal, not news about the upstream — the same
            # distinction `counts_as_failure` draws in the breaker. Whatever
            # actually broke is remembered rather than overwritten, so a reader
            # of /readyz keeps being told "cannot connect" instead of watching
            # the real cause decay into "we have stopped trying" a few seconds
            # after the outage begins.
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
            # A non-taxonomy exception is a bug in the gateway rather than a
            # verdict on the upstream — but a prober that dies takes every
            # other upstream's monitoring with it, so it is caught, recorded
            # and logged loudly instead.
            logger.exception("health.probe_failed", extra={"upstream": name})
            self._update(
                name, UpstreamHealth.UNHEALTHY, error=type(exc).__name__, previous=previous
            )
        else:
            self._update(name, UpstreamHealth.HEALTHY, tool_count=len(tools), previous=previous)

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
            # Only transitions. A probe every fifteen seconds forever would
            # otherwise produce a log line every fifteen seconds forever, which
            # is the same mistake as logging every scrape.
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

    # -- the loop ----------------------------------------------------------

    async def run(self, *, sleep: Callable[[float], object] | None = None) -> None:
        """Probe forever. Cancelled by whoever started it.

        Probes immediately on entry rather than after one interval: a gateway
        that has just started knows nothing, and waiting fifteen seconds to
        find out is fifteen seconds of serving a catalogue nobody has checked.
        """
        rest = sleep or anyio.sleep
        while True:
            await self.probe_once()
            await rest(self._next_delay())  # type: ignore[misc]

    def _next_delay(self) -> float:
        """The interval, jittered.

        Every replica probing on the same tick is a synchronised burst against
        every upstream, from a component whose whole purpose is to avoid
        exactly that — the same reasoning as the retry backoff in task 13.
        """
        spread = self._interval * self._jitter
        return max(0.0, self._uniform(self._interval - spread, self._interval + spread))


def upstream_names(upstreams: Iterable[Upstream]) -> list[str]:
    """Convenience for logging and for the readiness payload's ordering."""
    return [u.config.name for u in upstreams]
