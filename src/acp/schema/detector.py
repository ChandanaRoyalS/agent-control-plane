"""Runtime drift detection, driven by the health prober's uncached catalogue fetches.

With probing disabled there is no runtime detection; ``acp schemas check`` is the only path.
Each event is logged once, but reports always measure distance from the committed baseline,
so drift stays visible in ``/schemas`` and the gauge until re-captured, and a restart
re-alerts.
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
        """Record one upstream's live catalogue and return the full report against the baseline.

        Only logging and the counter are de-duplicated.
        """
        self._known.add(upstream)
        self._observed = self._observed.with_upstream(upstream, result)
        report = self.report()

        for event in report.events:
            if event.key not in self._reported:
                self._announce(event)

        # Replaced, not unioned, so a reverted then repeated change alerts again.
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
        """Log a new event at WARNING (so it survives production filters) and count it."""
        logger.warning("schema.drift", extra={**event.as_dict(), "detail": event.describe()})
        metrics.record_schema_drift(upstream=event.upstream, kind=str(event.kind))

    def _publish(self, report: DriftReport) -> None:
        """Set the outstanding gauge for every known upstream, including clean ones (zero)."""
        for upstream in self._known:
            metrics.observe_schema_drift(
                upstream=upstream, outstanding=len(report.for_upstream(upstream))
            )
