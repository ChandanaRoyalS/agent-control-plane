"""Structured logging, built on the standard library.

Two decisions shape this module, and both are argued in ADR 0007.

**Events, not sentences.** A log line is ``logger.info("upstream.call",
extra={...})`` rather than ``logger.info("called %s on %s in %dms", ...)``. The
message becomes a stable identifier you can group and alert on, and everything
variable becomes a field you can filter by. Sentences are pleasant to read and
impossible to query: ``upstream mock-a failed during tools/list`` cannot be
counted per upstream without a regular expression that breaks the first time
someone rewords the message.

**No structlog.** Every library in this stack — httpx, uvicorn, the MCP SDK —
logs through ``logging``, so a bridge from the standard library is needed
whatever else is chosen. Building on it directly means one pipeline instead of
two and one dependency fewer, at the cost of the ~150 lines below.

The pieces: a ``Filter`` that merges request-scoped context into every record,
a formatter that renders JSON, a formatter that renders something a human can
read at a terminal, and a redaction pass that runs over both.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from acp.observability import context

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
"""Matched as *substrings* of a normalised key, deliberately.

Over-redacting is the correct direction to fail. A false positive costs one
confusing debugging session; a false negative writes a live credential into a
log aggregator that a dozen people and three vendors can read, and that cannot
be taken back. `refresh_token`, `x-api-key` and `clientSecret` all have to be
caught without anyone remembering to add them.
"""

_MAX_DEPTH: Final = 6
"""Structures deeper than this are summarised rather than walked.

Logging is not the place to discover that a tool returned a deeply nested or
self-referential payload. A recursion limit blown inside a log call takes down
the request it was trying to describe.
"""


def _is_sensitive(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalised = "".join(ch for ch in key.lower() if ch.isalnum() or ch == "_")
    return any(
        fragment.replace("_", "") in normalised.replace("_", "")
        for fragment in _SENSITIVE_FRAGMENTS
    )


def redact(value: object, *, _depth: int = 0) -> object:
    """Replace secret-shaped values anywhere in a structure.

    Walks mappings and sequences because secrets are rarely top level — an
    upstream's headers arrive as a nested dict, and a request dump nests further
    still.
    """
    if _depth >= _MAX_DEPTH:
        return f"<truncated {type(value).__name__}>"

    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive(key) else redact(item, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, str | bytes):
        # Ahead of the Sequence check: a string is a sequence of strings, and
        # walking it would produce a list of characters.
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
"""Attributes the logging module puts on every record itself.

Anything on a record that is *not* in this set arrived via ``extra=`` and is
therefore one of our fields. Diffing against a known set is the only way to
recover them — the standard library offers no accessor.
"""


class ContextFilter(logging.Filter):
    """Copies request-scoped context onto each record as it is emitted.

    A filter rather than a formatter concern, because the context has to be read
    in the task that *logged* the line. Formatting can happen later, on a
    different thread if a queue handler is added, by which point the contextvars
    of the originating task are long gone.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in context.current().items():
            if not hasattr(record, key):
                # An explicit `extra=` on the call site wins over ambient
                # context: the specific beats the general.
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

        # `default=str` so an unserialisable value degrades to its repr instead
        # of raising. A logging call that throws is strictly worse than a log
        # line that is slightly lossy — it takes down the request it was
        # describing, and usually in the error path where the log mattered most.
        return json.dumps(redact(payload), default=str, separators=(",", ":"))


class ConsoleFormatter(logging.Formatter):
    """Human-readable, for a developer watching a terminal.

    The same fields, laid out for eyes rather than for a parser. Worth the extra
    class: JSON on a terminal is unreadable enough that people disable
    structured logging locally and then never see the fields they will have to
    rely on in production.
    """

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
"""Third-party loggers turned down to WARNING.

httpx logs a line per request at INFO. The gateway makes one upstream request
per tool call and several per catalogue fetch, so at INFO the useful signal is
outnumbered several to one by an echo of what the gateway is already reporting
with more context.
"""

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
    """Install the gateway's logging pipeline on the root logger.

    Idempotent: it replaces its own handler rather than adding another. Calling
    it twice is easy to do — a CLI entry point and a test fixture both want to —
    and the symptom of getting it wrong is every line appearing twice, which
    people tend to diagnose as a bug in the code doing the logging.

    Writes to stderr, not stdout. Stdout belongs to the program's actual output;
    a gateway that mixes logs into it cannot be piped anywhere useful.
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
