"""Unit tests for the logging pipeline.

Two properties carry most of the weight. Redaction must not be defeatable by
nesting or by a key nobody thought to list, because a leaked credential cannot
be un-leaked. And a logging call must never raise — a formatter that throws on
an unusual value takes down the request it was describing, invariably in the
error path where the log mattered most.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import pytest

from acp.observability import context
from acp.observability.log import (
    REDACTED,
    ConsoleFormatter,
    ContextFilter,
    JsonFormatter,
    configure_logging,
    formatter_for,
    redact,
)


@pytest.fixture(autouse=True)
def _clean_context() -> Any:
    context.clear()
    yield
    context.clear()


def record(
    event: str = "test.event", level: int = logging.INFO, **fields: Any
) -> logging.LogRecord:
    rec = logging.LogRecord("acp.test", level, "test.py", 1, event, None, None)
    for key, value in fields.items():
        setattr(rec, key, value)
    return rec


def rendered(rec: logging.LogRecord) -> dict[str, Any]:
    parsed = json.loads(JsonFormatter().format(rec))
    assert isinstance(parsed, dict)
    return parsed


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "authorization",
        "Authorization",
        "AUTHORIZATION",
        "x-api-key",
        "api_key",
        "apiKey",
        "clientSecret",
        "client_secret",
        "refresh_token",
        "access_token",
        "Cookie",
        "password",
        "passphrase",
        "private_key",
        "aws_credentials",
    ],
)
def test_secret_shaped_keys_are_redacted(key: str) -> None:
    """Substring matching on a normalised key, so nobody has to maintain an
    exhaustive list of every spelling a header might arrive in."""
    assert redact({key: "s3cret"}) == {key: REDACTED}


@pytest.mark.parametrize("key", ["upstream", "tool", "duration_ms", "status", "user_id", "path"])
def test_ordinary_keys_survive(key: str) -> None:
    assert redact({key: "value"}) == {key: "value"}


def test_redaction_reaches_nested_values() -> None:
    """Secrets are rarely at the top level — headers arrive nested, and a
    request dump nests further still."""
    payload = {"request": {"headers": {"authorization": "Bearer abc", "accept": "json"}}}

    assert redact(payload) == {
        "request": {"headers": {"authorization": REDACTED, "accept": "json"}}
    }


def test_redaction_reaches_inside_lists() -> None:
    payload = {"upstreams": [{"name": "mock-a", "token": "abc"}, {"name": "mock-b"}]}

    assert redact(payload) == {
        "upstreams": [{"name": "mock-a", "token": REDACTED}, {"name": "mock-b"}]
    }


def test_strings_are_not_walked_as_sequences() -> None:
    """A string is a sequence of strings; walking one yields a list of
    characters and turns every message into unreadable JSON."""
    assert redact({"event": "hello"}) == {"event": "hello"}


def test_deep_structures_are_truncated_rather_than_recursed() -> None:
    """A tool result the gateway did not author must not be able to blow the
    recursion limit inside a log call."""
    deep: dict[str, Any] = {"level": 0}
    node = deep
    for i in range(1, 40):
        node["child"] = {"level": i}
        node = node["child"]

    result = redact(deep)

    assert "truncated" in json.dumps(result)


def test_redaction_happens_on_the_way_out() -> None:
    """The guarantee is about what reaches the handler, not about callers
    remembering to scrub before they log."""
    output = rendered(record("http.request", headers={"authorization": "Bearer abc"}))

    assert output["headers"] == {"authorization": REDACTED}
    assert "Bearer abc" not in json.dumps(output)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def test_the_message_becomes_a_stable_event_name() -> None:
    """Events, not sentences: `upstream.call` can be counted; "called search on
    mock-a in 12ms" needs a regular expression that breaks on the first
    rewording."""
    output = rendered(record("upstream.call", upstream="mock-a", duration_ms=12.5))

    assert output["event"] == "upstream.call"
    assert output["upstream"] == "mock-a"
    assert output["duration_ms"] == 12.5


def test_standard_record_attributes_do_not_leak_into_the_payload() -> None:
    """Only `extra=` fields and the few chosen top-level keys, or every line
    carries a dozen fields nobody queries."""
    output = rendered(record("test.event", upstream="mock-a"))

    assert set(output) == {"timestamp", "level", "logger", "event", "upstream"}


def test_output_is_one_line() -> None:
    """A multi-line record breaks every line-oriented log shipper there is."""
    assert "\n" not in JsonFormatter().format(record("test.event", note="a\nb"))


def test_an_unserialisable_value_degrades_instead_of_raising() -> None:
    """A logging call that throws is worse than a log line that is lossy."""

    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    output = rendered(record("test.event", thing=Opaque()))

    assert output["thing"] == "<opaque>"


def test_exceptions_are_rendered_into_the_payload() -> None:
    """An error event without its traceback is a notification, not a clue."""

    def boom() -> None:
        raise ValueError("boom")

    try:
        boom()
    except ValueError:
        rec = record("test.failed", level=logging.ERROR)
        rec.exc_info = sys.exc_info()

    output = rendered(rec)

    assert "ValueError: boom" in output["exception"]


def test_the_timestamp_is_utc_and_sortable() -> None:
    """Log lines are read after being merged from several machines; a local
    timestamp makes that merge meaningless."""
    output = rendered(record())

    assert output["timestamp"].endswith("+00:00")


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def test_bound_context_appears_on_every_line() -> None:
    rec = record("upstream.call")

    with context.request("req-1"):
        ContextFilter().filter(rec)

    assert rendered(rec)["request_id"] == "req-1"


def test_an_explicit_field_beats_ambient_context() -> None:
    """The specific beats the general — otherwise a handler that knows the real
    upstream gets overwritten by whatever was bound earlier."""
    rec = record("upstream.call", upstream="mock-b")

    with context.context(upstream="mock-a"):
        ContextFilter().filter(rec)

    assert rendered(rec)["upstream"] == "mock-b"


def test_no_context_is_not_an_error() -> None:
    """Plenty of logging happens at startup, before any request exists."""
    rec = record("gateway.starting")
    ContextFilter().filter(rec)

    assert "request_id" not in rendered(rec)


# ---------------------------------------------------------------------------
# Console output and setup
# ---------------------------------------------------------------------------


def test_console_output_shows_the_fields() -> None:
    line = ConsoleFormatter().format(record("upstream.call", upstream="mock-a", duration_ms=3))

    assert "upstream.call" in line
    assert "upstream=mock-a" in line
    assert "duration_ms=3" in line


def test_console_output_redacts_too() -> None:
    """The developer's terminal is not a safe place for a credential either —
    it ends up in scrollback, screenshots and pasted bug reports."""
    line = ConsoleFormatter().format(record("http.request", authorization="Bearer abc"))

    assert "Bearer abc" not in line
    assert REDACTED in line


@pytest.mark.parametrize(
    ("fmt", "expected"), [("json", JsonFormatter), ("console", ConsoleFormatter)]
)
def test_the_format_is_selectable(fmt: str, expected: type[logging.Formatter]) -> None:
    assert isinstance(formatter_for(fmt), expected)


def test_an_unknown_format_fails_loudly() -> None:
    """A typo in `ACP_LOG_FORMAT` must not silently fall back — the fallback
    would be discovered months later as "why is production logging plain text"."""
    with pytest.raises(ValueError, match="unknown log format"):
        formatter_for("jsonl")


def test_configuring_twice_does_not_double_every_line() -> None:
    """Easy to do — a CLI entry point and a test fixture both want to call it —
    and the symptom is usually misdiagnosed as a bug in the calling code."""
    root = logging.getLogger()
    before = len(root.handlers)

    configure_logging("INFO", "json")
    configure_logging("DEBUG", "json")

    added = len(root.handlers) - before
    assert added == 1

    for handler in [h for h in root.handlers if h.name == "acp"]:
        root.removeHandler(handler)


def test_auto_picks_json_when_stderr_is_not_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`auto` is the production default, so this is the branch that actually
    decides what a deployed gateway writes. Untested, "production is logging
    plain text" is a discovery someone makes months later."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)

    assert isinstance(formatter_for("auto"), JsonFormatter)


def test_auto_picks_console_at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)

    assert isinstance(formatter_for("auto"), ConsoleFormatter)


def test_console_output_includes_a_traceback() -> None:
    """The terminal is where an exception is most likely to be read, and a
    one-line error with no traceback is the least useful thing to print."""

    def boom() -> None:
        raise ValueError("boom")

    try:
        boom()
    except ValueError:
        rec = record("test.failed", level=logging.ERROR)
        rec.exc_info = sys.exc_info()

    assert "ValueError: boom" in ConsoleFormatter().format(rec)


def test_a_non_string_key_is_not_treated_as_a_secret() -> None:
    """JSON keys are strings, but a dict logged straight from Python need not
    be — and `redact` must not raise on one."""
    assert redact({1: "value", None: "other"}) == {"1": "value", "None": "other"}
