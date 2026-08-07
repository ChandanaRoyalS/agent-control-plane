"""Making the gateway's behaviour visible from outside it.

Structured logging lands here in task 15; tracing (16) and metrics (17) join it.
They are kept together because they answer the same question at different
resolutions — what happened, in what order, and how often — and because they all
depend on the same request-scoped context.
"""

from acp.observability.context import bind, new_request_id, request, request_id
from acp.observability.log import (
    REDACTED,
    ConsoleFormatter,
    ContextFilter,
    JsonFormatter,
    configure_logging,
    redact,
)
from acp.observability.middleware import RequestContextMiddleware
from acp.observability.tracing import (
    TRACING_AVAILABLE,
    client_span,
    configure_tracing,
    current_trace_context,
    trace_ids,
)

__all__ = [
    "REDACTED",
    "TRACING_AVAILABLE",
    "ConsoleFormatter",
    "ContextFilter",
    "JsonFormatter",
    "RequestContextMiddleware",
    "bind",
    "client_span",
    "configure_logging",
    "configure_tracing",
    "current_trace_context",
    "new_request_id",
    "redact",
    "request",
    "request_id",
    "trace_ids",
]
