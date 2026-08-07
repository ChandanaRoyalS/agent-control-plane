"""Distributed tracing for the half of the gateway the SDK does not instrument.

The MCP SDK ships `OpenTelemetryMiddleware` enabled by default, so every request
the gateway *receives* already produces a `SERVER` span with the parent
extracted from `params._meta`. That half is done, and duplicating it would
produce two spans per request describing the same thing.

What the SDK cannot instrument is the half ADR 0005 deliberately hand-rolled:
the outbound client. Without the code here, a trace would show the agent's
request arriving and then stop dead at the gateway boundary — which is precisely
the boundary a trace exists to cross. Every upstream call gets a `CLIENT` span,
and the W3C trace context is injected into the outbound `params._meta` so an
upstream that is itself instrumented continues the same trace rather than
starting a new one.

**Trace context travels in `params._meta`, unprefixed.** Not in an HTTP header,
and not namespaced. MCP's SEP-414 makes `traceparent`, `tracestate` and
`baggage` an explicit, documented exception to the DNS-prefixing rule that
`acp.upstream.envelope` otherwise follows, precisely so that traces and log
correlation do not break across implementations that disagree about the prefix.

**Import guarded, and always degrading to a no-op.** OpenTelemetry is a declared
dependency, so in a correctly installed gateway this never falls through. It is
guarded anyway for two reasons: telemetry failing must never be able to take the
gateway down, and every test that does not configure tracing exercises the
no-op path — which is nearly all of them, and is the path most deployments run
until someone turns an exporter on.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from acp import __version__

logger = logging.getLogger(__name__)

TRACER_NAME = "agent-control-plane"

KNOWN_EXPORTERS = ("otlp", "console")
"""Exporters this gateway knows how to build.

An unrecognised value is refused rather than quietly treated as OTLP. Silently
falling back means a typo in `OTEL_TRACES_EXPORTER` produces a gateway that
looks configured, exports to the wrong place or to nowhere, and gives no signal
until someone goes looking for traces that were never going to arrive.
"""

try:  # pragma: no cover - exercised by whichever branch the environment has
    from opentelemetry import propagate, trace
    from opentelemetry.trace import SpanKind, StatusCode

    TRACING_AVAILABLE = True
except ImportError:  # pragma: no cover
    TRACING_AVAILABLE = False

# The API is imported at module scope because it is needed on every request; the
# SDK is imported inside `configure_tracing` because it is needed once, at
# startup, and only when an exporter is actually wanted. That split is
# OpenTelemetry's own guidance — libraries depend on the API, applications on
# the SDK — and it keeps the import cost off the request path.


# ---------------------------------------------------------------------------
# Reading the current trace
# ---------------------------------------------------------------------------


def trace_ids() -> Mapping[str, str]:
    """The active trace and span IDs, W3C-formatted, or empty outside a span.

    Merged onto every log record by ``ContextFilter``, which is what finally
    closes the loop task 15 opened: a log line can be pivoted to its trace, and
    a slow span can be pivoted to the log lines explaining why.

    Hex-formatted to fixed width rather than printed as integers, because that
    is the form every tracing backend's search box expects.
    """
    if not TRACING_AVAILABLE:
        return {}
    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return {}
    return {
        "trace_id": format(span_context.trace_id, "032x"),
        "span_id": format(span_context.span_id, "016x"),
    }


def current_trace_context() -> dict[str, str]:
    """The W3C carrier to attach to an outbound request's ``params._meta``.

    Empty when nothing is being traced, which matters: an empty mapping adds no
    keys, so an untraced gateway sends exactly the request it sent before this
    module existed.
    """
    if not TRACING_AVAILABLE:
        return {}
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return carrier


# ---------------------------------------------------------------------------
# Creating spans
# ---------------------------------------------------------------------------


@contextmanager
def client_span(name: str, attributes: Mapping[str, Any]) -> Iterator[Any]:
    """A ``CLIENT`` span around one outbound request.

    ``record_exception`` is off, and the failure is described by ``error.type``
    and a status instead. An exception recorded in full carries its message and
    stack trace into the span, and exception messages here routinely quote URLs,
    arguments and upstream responses — the same reasoning that keeps
    ``gen_ai.tool.call.arguments`` out of ``semconv``, and the same choice the
    SDK's own middleware makes for exactly the same stated reason.
    """
    if not TRACING_AVAILABLE:
        yield None
        return

    tracer = trace.get_tracer(TRACER_NAME, __version__)
    with tracer.start_as_current_span(
        name,
        kind=SpanKind.CLIENT,
        attributes=dict(attributes),
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        yield span


def mark_failed(span: Any, attributes: Mapping[str, Any], description: str) -> None:
    """Record a failure on a span, without leaking the exception's message.

    ``description`` is expected to be a fixed, low-cardinality string chosen by
    the caller rather than ``str(exc)``.
    """
    if span is None or not TRACING_AVAILABLE:
        return
    span.set_attributes(dict(attributes))
    span.set_status(StatusCode.ERROR, description)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def configure_tracing(service_name: str = TRACER_NAME) -> bool:
    """Install a tracer provider and an OTLP exporter. Returns whether it did.

    Driven by OpenTelemetry's **standard** environment variables —
    ``OTEL_TRACES_EXPORTER``, ``OTEL_EXPORTER_OTLP_ENDPOINT``,
    ``OTEL_SERVICE_NAME`` — rather than by ``ACP_``-prefixed settings of our
    own. Anyone who has deployed an instrumented service already knows these,
    every sidecar and operator already sets them, and inventing a parallel
    vocabulary for a standard that already exists is how a service becomes
    annoying to run.

    Tracing is off unless ``OTEL_TRACES_EXPORTER`` names an exporter, so the
    default posture is "no telemetry leaves this process".

    Never raises. A gateway that refuses to start because a collector is
    unreachable has turned an observability problem into an outage.
    """
    exporter_name = os.environ.get("OTEL_TRACES_EXPORTER", "none").strip().lower()
    if exporter_name in {"", "none"}:
        logger.info("tracing.disabled", extra={"reason": "OTEL_TRACES_EXPORTER is not set"})
        return False

    if exporter_name not in KNOWN_EXPORTERS:
        logger.warning(
            "tracing.unknown_exporter",
            extra={"exporter": exporter_name, "known": list(KNOWN_EXPORTERS)},
        )
        return False

    if not TRACING_AVAILABLE:
        logger.warning(
            "tracing.unavailable",
            extra={"reason": "opentelemetry is not installed", "exporter": exporter_name},
        )
        return False

    try:
        return _install(service_name, exporter_name)
    except Exception:
        logger.exception("tracing.setup_failed", extra={"exporter": exporter_name})
        return False


def _install(service_name: str, exporter_name: str) -> bool:
    # Imported here rather than at module scope: the SDK is only needed by the
    # process that exports, and an import inside a function is cheaper than a
    # dependency the request path never uses.
    from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource  # noqa: PLC0415
    from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: PLC0415

    resource = Resource.create(
        {
            SERVICE_NAME: os.environ.get("OTEL_SERVICE_NAME", service_name),
            SERVICE_VERSION: __version__,
        }
    )
    provider = TracerProvider(resource=resource)

    if exporter_name == "console":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter  # noqa: PLC0415

        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:  # "otlp" — the only other member of KNOWN_EXPORTERS
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        # Batched, not simple: a span exported synchronously puts a network call
        # on the request path, which means a slow collector becomes slow tool
        # calls — the exact failure the breaker exists to prevent, reintroduced
        # by the thing meant to observe it.
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

    trace.set_tracer_provider(provider)
    logger.info(
        "tracing.enabled",
        extra={
            "exporter": exporter_name,
            "endpoint": os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "default"),
            "service_name": resource.attributes.get(SERVICE_NAME),
        },
    )
    return True
