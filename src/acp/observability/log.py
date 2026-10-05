"""Structured logging on the standard library, without structlog (ADR 0007).

Messages are stable event names (``logger.info("upstream.call", extra={...})``) with variable
data in fields. Provides a context filter, JSON and console formatters, and `redact`.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from acp.observability import context, tracing

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

REDACTED: Final = "[redacted]"

_SENSITIVE_FRAGMENTS: Final = (
    "authorization",
    "auth_header",
    "cookie",
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "apikey",
    "api_key",
    "private_key",
    "bearer",
    "session_key",
    "signature",
)
"""Matched as substrings of a normalised key, so `refresh_token` or `x-api-key` are caught.

Over-redaction is the intended failure direction.
"""

_MAX_DEPTH: Final = 6
"""Deeper structures are summarised, so a nested or cyclic payload cannot blow recursion."""


def _is_sensitive(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalised = "".join(ch for ch in key.lower() if ch.isalnum() or ch == "_")
    return any(
        fragment.replace("_", "") in normalised.replace("_", "")
        for fragment in _SENSITIVE_FRAGMENTS
    )


def redact(value: object, *, _depth: int = 0) -> object:
    """Replace values under secret-shaped keys anywhere in nested mappings and sequences."""
    if _depth >= _MAX_DEPTH:
        return f"<truncated {type(value).__name__}>"

    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive(key) else redact(item, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, str | bytes):
        # Before the Sequence check, or a string would become a list of characters.
        return value
    if isinstance(value, Sequence):
        return [redact(item, _depth=_depth + 1) for item in value]
    return value


# ---------------------------------------------------------------------------
# Getting context onto the record
# ---------------------------------------------------------------------------

_RESERVED: Final = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "stacklevel",
        "taskName",
        "thread",
        "threadName",
    }
)
"""Standard `LogRecord` attributes; anything else on a record came from ``extra=``."""


class ContextFilter(logging.Filter):
    """Copies request context onto each record in the logging task (formatting may run later)."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Bound context overrides trace IDs; an explicit `extra=` overrides both.
        for key, value in {**tracing.trace_ids(), **context.current()}.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


def _fields(record: logging.LogRecord) -> dict[str, Any]:
    return {key: value for key, value in record.__dict__.items() if key not in _RESERVED}


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """One JSON object per line, for a log aggregator to parse."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
            **_fields(record),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        # `default=str`: a lossy line beats a logging call that raises mid-request.
        return json.dumps(redact(payload), default=str, separators=(",", ":"))


class ConsoleFormatter(logging.Formatter):
    """The same fields, human-readable, for a terminal."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, tz=UTC).strftime("%H:%M:%S.%f")[:-3]
        fields = redact(_fields(record))
        rendered = ""
        if isinstance(fields, dict) and fields:
            rendered = " " + " ".join(f"{key}={value}" for key, value in sorted(fields.items()))

        line = f"{stamp} {record.levelname:<8} {record.name} {record.getMessage()}{rendered}"
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

QUIET_LOGGERS: Final = {
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
}
"""Third-party loggers turned down to WARNING; httpx's per-request INFO lines duplicate ours."""

_HANDLER_NAME: Final = "acp"


def formatter_for(fmt: str) -> logging.Formatter:
    """Pick a formatter. ``auto`` means JSON unless stderr is a terminal."""
    if fmt == "auto":
        fmt = "console" if sys.stderr.isatty() else "json"
    if fmt == "console":
        return ConsoleFormatter()
    if fmt == "json":
        return JsonFormatter()
    msg = f"unknown log format {fmt!r}: expected 'json', 'console' or 'auto'"
    raise ValueError(msg)


def configure_logging(level: str = "INFO", fmt: str = "auto") -> None:
    """Install the gateway's stderr logging handler on the root logger.

    Idempotent: replaces its own handler rather than adding a second one.
    """
    root = logging.getLogger()
    for existing in [h for h in root.handlers if h.name == _HANDLER_NAME]:
        root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stderr)
    handler.name = _HANDLER_NAME
    handler.setFormatter(formatter_for(fmt))
    handler.addFilter(ContextFilter())

    root.addHandler(handler)
    root.setLevel(level.upper())

    for name, quiet_level in QUIET_LOGGERS.items():
        logging.getLogger(name).setLevel(quiet_level)
