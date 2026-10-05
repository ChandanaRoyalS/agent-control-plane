"""Tracing for the outbound client the SDK does not instrument (ADR 0009, ADR 0005).

The SDK already emits `SERVER` spans; this adds a `CLIENT` span per upstream call and injects
W3C context into `params._meta`, unprefixed per MCP SEP-414. The OpenTelemetry import is
guarded and everything degrades to a no-op, so telemetry can never take the gateway down.
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
"""Exporters this gateway can build; anything else disables tracing with a warning."""

try:  # pragma: no cover - exercised by whichever branch the environment has
    from opentelemetry import propagate, trace
    from opentelemetry.trace import SpanKind, StatusCode

    TRACING_AVAILABLE = True
except ImportError:  # pragma: no cover
    TRACING_AVAILABLE = False

# The API is imported here; the SDK only in `_install`, at startup, when exporting.


# ---------------------------------------------------------------------------
# Reading the current trace
# ---------------------------------------------------------------------------


def trace_ids() -> Mapping[str, str]:
    """The active trace and span IDs as fixed-width hex, or empty outside a span.

    ``ContextFilter`` merges these onto every log record.
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
    """The W3C carrier for an outbound ``params._meta``; empty (adds nothing) when untraced."""
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

    Exceptions are not recorded, since their messages can quote URLs, arguments and responses;
    use `mark_failed` instead.
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
    """Mark a span failed; ``description`` must be a fixed string, never ``str(exc)``."""
    if span is None or not TRACING_AVAILABLE:
        return
    span.set_attributes(dict(attributes))
    span.set_status(StatusCode.ERROR, description)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def configure_tracing(service_name: str = TRACER_NAME) -> bool:
    """Install a tracer provider and exporter from the standard ``OTEL_*`` variables.

    Off unless ``OTEL_TRACES_EXPORTER`` names a known exporter. Never raises.

    Returns:
        Whether tracing was installed.
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

        # Batched so a slow collector never adds latency to the request path.
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
