"""Prometheus metrics.

Traces answer "what happened in this one request". Metrics answer "what is
happening across all of them" — how often, how slowly, and how much of it is
failing. They are cheap to add now and are the thing you want the instant you
load test, which is task 60.

Everything here is deliberately small in cardinality, and that is the whole
design problem. A Prometheus time series exists for every distinct combination
of label values, and each one costs memory in the server forever. The failure
mode is not a slow dashboard; it is an observability system that falls over
because of what it was asked to observe.

Three rules follow from that, and each is enforced below rather than left to
whoever adds the next metric:

**No label whose values come from a caller.** A tool name looks safe — a real
catalogue has tens of them — but the name in a `tools/call` is chosen by the
agent, not by us. An agent calling a hundred thousand nonexistent tools would
mint a hundred thousand series. So the tool label is resolved against the tools
actually known, and anything else becomes ``unknown``.

**No arguments, ever.** Same reasoning as the span attributes in ``semconv``,
one step more severe: a span with a high-cardinality attribute is merely large,
a metric with one is unbounded.

**Seconds, not milliseconds.** Prometheus convention is base units. The logs
carry ``duration_ms`` because a human reads them; the histogram carries seconds
because a query engine reads it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Final

logger = logging.getLogger(__name__)

NAMESPACE: Final = "acp"

UNKNOWN_TOOL: Final = "unknown"
"""Stand-in for a tool name that is not in any upstream's catalogue.

The cardinality guard. Without it, `tools/call` on a name nobody exposes is a
free write into the metrics server's memory, repeatable as fast as an agent can
issue requests.
"""

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
"""Chosen against this system's timeouts, not left at the library defaults.

Prometheus' default buckets stop at 10 seconds. The default upstream read
timeout is 30, so every timed-out call would land in the overflow bucket
together — and a p99 computed from a bucket with no upper bound is not a number,
it is a guess. The tail here is where the interesting failures live, so the tail
is where the resolution has to be.
"""

BREAKER_STATES: Final = ("closed", "open", "half_open")
"""Exported as a *state set*: one series per state, exactly one of them 1.

The tempting alternative is a single gauge holding 0, 1 or 2. It is smaller and
it is unreadable — nobody remembers whether 2 means open, and
`max_over_time(breaker == 2)` is a query you have to decode rather than read.
"""

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
    schema_drift: Any
    schema_drift_outstanding: Any


def _build() -> _Collectors | None:
    """Construct the collectors against a registry of our own.

    A private ``CollectorRegistry`` rather than the library's global one. The
    global registry raises on duplicate registration, which makes it impossible
    to build the metrics twice in one process — and a module-level global that
    survives between tests is exactly the mistake that made a tracing test leak
    an exporter into every test after it.
    """
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
            # Deliberately no `tool` label: buckets multiply, and
            # upstreams x tools x buckets is how a histogram becomes the
            # largest thing in your metrics server.
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
            # Both labels are closed sets: upstream names come from the config
            # file and `kind` is a StrEnum. Deliberately *not* labelled by tool
            # — a hostile upstream chooses its own tool names, and a label value
            # chosen by the thing being monitored is unbounded by construction.
            ["upstream", "kind"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        result_cache=Counter(
            "result_cache_total",
            "Tool-result cache lookups, by outcome.",
            # `outcome` only. The principal is unbounded by construction, and it
            # is also a disclosure: a per-principal hit-rate series on a scrape
            # endpoint is a record of who asked for what and when. The tool name
            # is bounded but omitted for the same reason — hit rate per tool is a
            # tuning question, and this counter answers a correctness one.
            ["outcome"],
            namespace=NAMESPACE,
            registry=registry,
        ),
        credential_cache=Counter(
            "credential_cache_total",
            "Exchanged-credential cache lookups, by outcome.",
            # `outcome` only, and emphatically not the principal. Subjects are
            # unbounded by construction — one label value per human the gateway
            # has ever served — and a metric that grows with your user base is a
            # metric that eventually takes the scrape endpoint down. The
            # audience is bounded but omitted too: hit rate per upstream is a
            # tuning question, and this counter exists to answer a correctness
            # one, which is whether the thing caches at all.
            ["outcome"],
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
    """Reduce a tool name to something safe to use as a label value.

    ``None`` means the operation has no tool, which is a legitimate and bounded
    value. A name that is not in ``known`` becomes ``unknown`` — because the
    name in a request is chosen by the caller, and a label value chosen by a
    caller is an unbounded write into someone else's memory.

    Passing ``known=None`` skips the check, and is only correct where the name
    has already been resolved against a catalogue.
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
    """One attempt beyond the first.

    Worth its own counter rather than being inferred from the call counter: a
    rising retry rate against a flat error rate is an upstream that is degrading
    but still succeeding, which is the earliest useful warning this system
    produces.
    """
    if _C is None:
        return
    _C.upstream_retries.labels(upstream, method).inc()


def observe_breaker(*, upstream: str, state: str) -> None:
    """Publish a breaker transition. Pushed, not scraped, because transitions
    are rare and the alternative is threading a metrics dependency through the
    registry to reach the guard at scrape time."""
    if _C is None:
        return
    for candidate in BREAKER_STATES:
        _C.breaker_state.labels(upstream, candidate).set(1 if candidate == state else 0)


def observe_bulkhead(*, upstream: str, in_flight: int, capacity: int) -> None:
    """Publish concurrency. Capacity is exported alongside the count so
    saturation is `in_flight / capacity` rather than a number a reader has to
    already know the limit to interpret."""
    if _C is None:
        return
    _C.bulkhead_in_flight.labels(upstream).set(in_flight)
    _C.bulkhead_capacity.labels(upstream).set(capacity)


def record_result_cache(*, outcome: str) -> None:
    """One tool-result cache lookup (task 43).

    The interesting failure is silent in both directions. A key too *specific*
    still returns correct results and simply never hits, so the estate serves
    every call and nobody notices. A key too *broad* is a data breach whose only
    artefact is its absence. Neither shows up in an error rate; the hit ratio is
    the only place either becomes visible.
    """
    if _C is None:
        return
    _C.result_cache.labels(outcome).inc()


def record_credential_cache(*, outcome: str) -> None:
    """One exchanged-credential cache lookup (task 30).

    Worth a counter rather than a log line because the interesting number is a
    *ratio* over time, and the interesting failure is silent: a cache whose key
    is too specific still works, still returns correct credentials, and simply
    never hits. Nothing breaks, the authorization server takes every request,
    and the only symptom is a miss rate that nobody is looking at.
    """
    if _C is None:
        return
    _C.credential_cache.labels(outcome).inc()


def record_schema_drift(*, upstream: str, kind: str) -> None:
    """One newly observed catalogue change (task 20).

    A counter rather than only a gauge, because the two answer different
    questions. The gauge says how much is outstanding right now; the counter
    says how often this upstream changes at all — and an upstream whose
    catalogue moves several times a week is a different kind of dependency from
    one that has not moved in a year, regardless of whether anything is
    outstanding at the moment you look.
    """
    if _C is None:
        return
    _C.schema_drift.labels(upstream, kind).inc()


def observe_schema_drift(*, upstream: str, outstanding: int) -> None:
    """How far this upstream currently sits from the acknowledged baseline.

    Zero is written explicitly for clean upstreams. A gauge only ever set when
    something is wrong holds its last bad value forever, which is how a
    dashboard ends up displaying an incident that ended yesterday.
    """
    if _C is None:
        return
    _C.schema_drift_outstanding.labels(upstream).set(outstanding)


# ---------------------------------------------------------------------------
# Exposition
# ---------------------------------------------------------------------------


def render() -> tuple[bytes, str]:
    """The scrape payload and its content type.

    Returns an empty body rather than raising when the library is absent, so
    `/metrics` answers honestly instead of returning a 500 that looks like the
    gateway is broken.
    """
    if _C is None:
        return b"", CONTENT_TYPE_LATEST
    payload: bytes = generate_latest(_C.registry)
    return payload, CONTENT_TYPE_LATEST
