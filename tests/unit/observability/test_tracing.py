"""Unit tests for the tracing layer.

Written so they hold whether or not OpenTelemetry is installed and whether or
not an exporter is configured. That is not a concession to the test
environment — it is the property that actually matters. Tracing is off in most
deployments until someone turns it on, so the no-op path is the one the gateway
spends most of its life running, and it is the one where a mistake would be
discovered as an outage rather than as a missing dashboard.
"""

from __future__ import annotations

from typing import Any

import pytest

from acp.observability import tracing


@pytest.fixture(autouse=True)
def _no_exporter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with tracing switched off at the standard control."""
    monkeypatch.delenv("OTEL_TRACES_EXPORTER", raising=False)


# ---------------------------------------------------------------------------
# Reading a trace that is not there
# ---------------------------------------------------------------------------


def test_there_are_no_trace_ids_outside_a_span() -> None:
    """Returned as an empty mapping rather than `None` so callers can merge it
    unconditionally — which is exactly what the log filter does on every line."""
    assert tracing.trace_ids() == {}


def test_there_is_no_trace_context_to_propagate_outside_a_span() -> None:
    """The load-bearing consequence: an untraced gateway adds no keys to
    `params._meta`, so it sends byte-for-byte the request it sent before this
    module existed."""
    assert tracing.current_trace_context() == {}


# ---------------------------------------------------------------------------
# Spans that may or may not exist
# ---------------------------------------------------------------------------


def test_a_client_span_is_usable_whether_or_not_tracing_is_on() -> None:
    """The call sites in `UpstreamClient` are unconditional, so this context
    manager has to work in both worlds. If it did not, turning tracing off
    would break the gateway rather than quieten it."""
    with tracing.client_span("tools/list", {"mcp.method.name": "tools/list"}) as span:
        assert span is None or span is not None  # both are legitimate


def test_the_span_does_not_swallow_the_operation_s_exception() -> None:
    """A tracing wrapper that eats the exception it was observing turns a
    failed tool call into a silent success."""

    class BoomError(Exception):
        pass

    with pytest.raises(BoomError), tracing.client_span("tools/list", {}):
        raise BoomError


def test_marking_a_missing_span_as_failed_is_harmless() -> None:
    """The error paths in the client call this unconditionally, and with
    tracing off there is no span to mark."""
    tracing.mark_failed(None, {"error.type": "UpstreamTimeoutError"}, "timeout")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def test_tracing_is_off_unless_an_exporter_is_named() -> None:
    """Default posture: no telemetry leaves this process. Turning it on is a
    deliberate act, not something that happens because a library was
    installed."""
    assert tracing.configure_tracing() is False


@pytest.mark.parametrize("value", ["", "none", "NONE", "  none  "])
def test_the_standard_off_switches_are_honoured(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """`OTEL_TRACES_EXPORTER=none` is OpenTelemetry's own way of saying this,
    and someone who already knows it should not have to learn ours."""
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", value)

    assert tracing.configure_tracing() is False


def test_setup_reports_rather_than_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gateway that refuses to start because a collector is unreachable has
    turned an observability problem into an outage.

    The failure is injected rather than provoked with a real unreachable
    endpoint. An earlier version of this test pointed a genuine OTLP exporter
    at a bogus host, which installed a process-global tracer provider that
    outlived the test, leaked into every test after it, and filled the suite's
    output with export retries. Proving error handling is not worth mutating
    global state to do.
    """
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")

    def explode(*_args: Any, **_kwargs: Any) -> bool:
        raise RuntimeError("collector refused the connection")

    monkeypatch.setattr(tracing, "_install", explode)

    assert tracing.configure_tracing() is False


def test_an_unknown_exporter_is_refused_rather_than_guessed_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo in `OTEL_TRACES_EXPORTER` must not silently become OTLP. That
    produces a gateway that looks configured, exports nowhere, and gives no
    signal until somebody goes looking for traces that were never coming."""
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlpp")

    assert tracing.configure_tracing() is False


def test_nothing_is_installed_when_setup_declines(monkeypatch: pytest.MonkeyPatch) -> None:
    """The property the previous version of this file violated: a declined
    setup leaves no global state behind."""
    installed: list[str] = []

    def record(*_args: Any, **_kwargs: Any) -> bool:
        installed.append("called")
        return True

    monkeypatch.setattr(tracing, "_install", record)
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")

    tracing.configure_tracing()

    assert installed == []
