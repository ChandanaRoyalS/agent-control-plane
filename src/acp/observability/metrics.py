"""Prometheus metrics, kept to bounded label cardinality.

No label takes caller-chosen values (unknown tool names become ``unknown``), arguments are
never labels, and durations are in seconds. Every recorder is a no-op when
``prometheus_client`` is not installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Final

logger = logging.getLogger(__name__)

NAMESPACE: Final = "acp"

UNKNOWN_TOOL: Final = "unknown"
"""Label for a tool name not in any catalogue, so callers cannot mint series."""

DURATION_BUCKETS: Final = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
)
"""Extends past the library's 10 s default to cover the 30 s default upstream read timeout."""

BREAKER_STATES: Final = ("closed", "open", "half_open")
"""Exported as a state set: one series per state, exactly one of them 1."""

try:  # pragma: no cover - depends on what the environment has installed
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    METRICS_AVAILABLE = True
except ImportError:  # pragma: no cover
    METRICS_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"


@dataclass(frozen=True, slots=True)
class _Collectors:
    """The metric objects, held together so they are built once or not at all."""

    registry: Any
    upstream_calls: Any
    upstream_duration: Any
    upstream_retries: Any
    breaker_state: Any
    bulkhead_in_flight: Any
    bulkhead_capacity: Any
    credential_cache: Any
    result_cache: Any
    audit_writes: Any
    firewall_decisions: Any
    firewall_findings: Any
    schema_drift: Any
    schema_drift_outstanding: Any


def _build() -> _Collectors | None:
    """Build the collectors on a private registry (the global one rejects re-registration)."""
    if not METRICS_AVAILABLE:
        return None

    registry = CollectorRegistry()
    return _Collectors(
        registry=registry,
        upstream_calls=Counter(
            "upstream_calls_total",
            "Requests the gateway made to an upstream, by outcome.",
            ["upstream", "method", "tool", "outcome"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        upstream_duration=Histogram(
            "upstream_call_duration_seconds",
            "Wall time of one upstream request, measured at the socket.",
            # No `tool` label: upstreams x tools x buckets would explode.
            ["upstream", "method"],
            namespace=NAMESPACE,
            registry=registry,
            buckets=DURATION_BUCKETS,
        ),
        upstream_retries=Counter(
            "upstream_retries_total",
            "Attempts made beyond the first, by upstream and operation.",
            ["upstream", "method"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        breaker_state=Gauge(
            "upstream_breaker_state",
            "Circuit breaker state, as a state set: exactly one state is 1.",
            ["upstream", "state"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        bulkhead_in_flight=Gauge(
            "upstream_calls_in_flight",
            "Calls currently holding a bulkhead slot.",
            ["upstream"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        bulkhead_capacity=Gauge(
            "upstream_bulkhead_capacity",
            "Configured concurrency limit, so saturation is a ratio not a guess.",
            ["upstream"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        schema_drift=Counter(
            "schema_drift_events_total",
            "Catalogue changes detected against the committed baseline, by kind.",
            # Closed sets only; not by tool, since an upstream chooses its own tool names.
            ["upstream", "kind"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        result_cache=Counter(
            "result_cache_total",
            "Tool-result cache lookups, by outcome.",
            # `outcome` only: a principal label is unbounded and discloses who asked what.
            ["outcome"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        credential_cache=Counter(
            "credential_cache_total",
            "Exchanged-credential cache lookups, by outcome.",
            # `outcome` only: subjects are unbounded.
            ["outcome"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        audit_writes=Counter(
            "audit_writes_total",
            "Audit chain entries, by whether they reached the sink.",
            # written/failed: the only signal for failures the audit log cannot record.
            ["outcome"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        firewall_decisions=Counter(
            "firewall_decisions_total",
            "Tool results screened by the injection firewall, by decision.",
            # Five decisions x two surfaces (result, catalogue); `clean` is counted (not
            # logged) so detections have a denominator.
            ["decision", "surface"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        firewall_findings=Counter(
            "firewall_findings_total",
            "Individual detector findings, by attack family and confidence.",
            # StrEnum labels only (fixed series); not by detector or caller-chosen tool.
            ["family", "confidence"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        schema_drift_outstanding=Gauge(
            "schema_drift_outstanding",
            "Changes not yet acknowledged by re-capturing the baseline.",
            ["upstream"],
            namespace=NAMESPACE,
            registry=registry,
        ),
    )


_C = _build()


# ---------------------------------------------------------------------------
# Label hygiene
# ---------------------------------------------------------------------------


def tool_label(tool: str | None, known: frozenset[str] | set[str] | None = None) -> str:
    """A bounded label value: ``none`` for no tool, ``unknown`` for a name not in ``known``.

    ``known=None`` skips the check; use it only for names already resolved against a catalogue.
    """
    if tool is None:
        return "none"
    if known is None:
        return tool
    return tool if tool in known else UNKNOWN_TOOL


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def record_upstream_call(
    *, upstream: str, method: str, tool: str, outcome: str, duration_seconds: float
) -> None:
    """One completed attempt against an upstream, however it ended."""
    if _C is None:
        return
    _C.upstream_calls.labels(upstream, method, tool, outcome).inc()
    _C.upstream_duration.labels(upstream, method).observe(duration_seconds)


def record_retry(*, upstream: str, method: str) -> None:
    """One attempt beyond the first; rising retries with flat errors means a degrading upstream."""
    if _C is None:
        return
    _C.upstream_retries.labels(upstream, method).inc()


def observe_breaker(*, upstream: str, state: str) -> None:
    """Publish a breaker transition (pushed, since transitions are rare)."""
    if _C is None:
        return
    for candidate in BREAKER_STATES:
        _C.breaker_state.labels(upstream, candidate).set(1 if candidate == state else 0)


def observe_bulkhead(*, upstream: str, in_flight: int, capacity: int) -> None:
    """Publish in-flight count and capacity, so saturation is a ratio."""
    if _C is None:
        return
    _C.bulkhead_in_flight.labels(upstream).set(in_flight)
    _C.bulkhead_capacity.labels(upstream).set(capacity)


def record_result_cache(*, outcome: str) -> None:
    """One tool-result cache lookup; the hit ratio is the only signal of a mis-scoped key."""
    if _C is None:
        return
    _C.result_cache.labels(outcome).inc()


def record_audit_write(*, outcome: str) -> None:
    """One audit write, ``written`` or ``failed``.

    Alert on ``failed``: with `ACP_AUDIT_REQUIRED` on, calls are being refused; off, the
    record has holes.
    """
    if _C is None:
        return
    _C.audit_writes.labels(outcome).inc()


def record_firewall_decision(*, decision: str, surface: str = "result") -> None:
    """One screened tool result; in report mode ``would_refuse`` estimates enforcement's cost."""
    if _C is None:
        return
    _C.firewall_decisions.labels(decision, surface).inc()


def record_firewall_finding(*, family: str, confidence: str) -> None:
    """One detector finding, by attack family and confidence (as the corpus is sliced)."""
    if _C is None:
        return
    _C.firewall_findings.labels(family, confidence).inc()


def record_credential_cache(*, outcome: str) -> None:
    """One exchanged-credential cache lookup; a key that never hits shows only here."""
    if _C is None:
        return
    _C.credential_cache.labels(outcome).inc()


def record_schema_drift(*, upstream: str, kind: str) -> None:
    """One newly observed catalogue change (how often an upstream changes, beside the gauge)."""
    if _C is None:
        return
    _C.schema_drift.labels(upstream, kind).inc()


def observe_schema_drift(*, upstream: str, outstanding: int) -> None:
    """Outstanding drift for this upstream; zero is set explicitly so stale values clear."""
    if _C is None:
        return
    _C.schema_drift_outstanding.labels(upstream).set(outstanding)


# ---------------------------------------------------------------------------
# Exposition
# ---------------------------------------------------------------------------


def render() -> tuple[bytes, str]:
    """The scrape payload and content type; an empty body if the library is absent."""
    if _C is None:
        return b"", CONTENT_TYPE_LATEST
    payload: bytes = generate_latest(_C.registry)
    return payload, CONTENT_TYPE_LATEST
