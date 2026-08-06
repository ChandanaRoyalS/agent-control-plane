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

__all__ = [
    "REDACTED",
    "ConsoleFormatter",
    "ContextFilter",
    "JsonFormatter",
    "RequestContextMiddleware",
    "bind",
    "configure_logging",
    "new_request_id",
    "redact",
    "request",
    "request_id",
]
