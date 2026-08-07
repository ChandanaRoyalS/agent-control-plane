"""Watching live catalogues go past, and saying something the first time one moves.

**Where the observation happens, and why it is the health prober.** The obvious
place is the request path — every ``tools/list`` an agent makes already carries a
fresh catalogue. It is the wrong place for three reasons. It puts hashing work on
a request an agent is waiting for; it sees nothing through a cache hit, which is
most requests once task 19 is on; and it is blind to any upstream nobody happens
to be calling — which is precisely the upstream whose description turning
malicious matters most, because the change lands before anyone is watching it.

The health monitor already fetches every upstream's catalogue on a timer, forces
past the cache to do it, and runs off the request path entirely. Drift detection
is that same fetch, read for a different purpose. So the detector is a hook the
prober calls, and the detection interval is the probe interval. The cost of that
choice, stated plainly: with probing disabled there is no runtime detection at
all, and ``acp schemas check`` is the only path.

**Alerts are edge-triggered; the baseline is not.** Reporting the same drift on
every probe forever would be the same mistake as logging every scrape, so an
event already reported is not reported again. But the *file* is left alone, so
the report always describes the distance from the acknowledged baseline rather
than from whatever was seen most recently. Two consequences follow, and both are
wanted. Drift stays visible in ``/schemas`` and in the gauge until somebody
re-captures — outstanding drift is a number that can be alerted on when it stays
non-zero for an hour. And a restart re-alerts, because a process restart is not
an acknowledgement of anything.
"""

from __future__ import annotations

import logging
from collections.abc import Collection

from acp.observability import metrics
from acp.schema.drift import DriftEvent, DriftReport, diff
from acp.schema.snapshot import SchemaSnapshot
from acp.upstream.models import ListToolsResult

logger = logging.getLogger(__name__)


class DriftDetector:
    """Holds the baseline, accumulates what has been observed, and reports."""

    def __init__(
        self,
        baseline: SchemaSnapshot | None,
        *,
        known: Collection[str] = (),
    ) -> None:
        self._baseline = baseline
        self._known = set(known)
        self._observed = SchemaSnapshot()
        self._reported: set[tuple[str, str, str, str]] = set()

    @property
    def has_baseline(self) -> bool:
        return self._baseline is not None

    # -- observing ---------------------------------------------------------

    def observe(self, upstream: str, result: ListToolsResult) -> DriftReport:
        """Record one upstream's live catalogue and report the current distance
        from the baseline.

        Returns the *whole* report rather than only what is new, so a caller can
        render current state; the de-duplication applies to logging and to the
        counter, not to what is returned.
        """
        self._known.add(upstream)
        self._observed = self._observed.with_upstream(upstream, result)
        report = self.report()

        for event in report.events:
            if event.key not in self._reported:
                self._announce(event)

        # Replaced rather than unioned. An event that has stopped appearing —
        # because somebody reverted the change — is forgotten, so if the same
        # change is made again it alerts again. Accumulating instead would mean
        # a repeated change is announced exactly once, ever, in the lifetime of
        # the process.
        self._reported = {event.key for event in report.events}
        self._publish(report)
        return report

    def report(self) -> DriftReport:
        """Everything currently different from the baseline."""
        return diff(self._baseline, self._observed, known=self._known)

    def snapshot(self) -> SchemaSnapshot:
        """What has been observed so far, in a form that could be captured."""
        return self._observed

    # -- internals ---------------------------------------------------------

    def _announce(self, event: DriftEvent) -> None:
        """One log line per new event.

        WARNING rather than INFO for everything including an added tool. The
        level here is not a judgement about severity; it is about whether the
        line survives a production log filter, and a catalogue changing under a
        gateway is not routine at any severity.
        """
        logger.warning("schema.drift", extra={**event.as_dict(), "detail": event.describe()})
        metrics.record_schema_drift(upstream=event.upstream, kind=str(event.kind))

    def _publish(self, report: DriftReport) -> None:
        """Set the outstanding gauge for every upstream, including the clean ones.

        Every known upstream, not just the ones with events — a gauge that is
        only ever written when something is wrong keeps reporting the last bad
        value after the problem is fixed, which is how a dashboard ends up
        showing an incident that ended yesterday.
        """
        for upstream in self._known:
            metrics.observe_schema_drift(
                upstream=upstream, outstanding=len(report.for_upstream(upstream))
            )
