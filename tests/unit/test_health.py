"""Unit tests for health probing and withdrawal.

The property that matters most is the one that fails *open*. A monitor that
never ran, or that has not yet reached an upstream, must not cause that
upstream's tools to disappear — otherwise a bug in the monitoring turns into a
gateway that serves nothing, which is a far worse outage than the one it was
built to describe.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import pytest

from acp.exceptions import (
    UpstreamCircuitOpenError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from acp.health import (
    HealthMonitor,
    HealthRecord,
    UpstreamHealth,
)
from acp.upstream import UpstreamConfig
from acp.upstream.models import ListToolsResult, ToolDefinition


class FakeUpstream:
    """An upstream whose `list_tools` does whatever the test says."""

    def __init__(self, name: str, outcome: Any = None) -> None:
        self.config = UpstreamConfig(name=name, url=f"http://{name}/mcp")
        self.outcome = outcome
        self.probes = 0
        self.invalidations = 0

    async def list_tools(self) -> ListToolsResult:
        self.probes += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return ListToolsResult(tools=list(self.outcome or []))

    async def invalidate(self) -> None:
        self.invalidations += 1

    async def call_tool(self, name: str, arguments: Any = None) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def aclose(self) -> None:  # pragma: no cover
        return None


def tool(name: str) -> ToolDefinition:
    return ToolDefinition.model_validate({"name": name, "inputSchema": {"type": "object"}})


def run(fn: Any) -> Any:
    return anyio.run(fn)


def monitor(*upstreams: FakeUpstream, **kwargs: Any) -> HealthMonitor:
    return HealthMonitor(list(upstreams), **kwargs)


# ---------------------------------------------------------------------------
# Failing open — the property that keeps a monitoring bug from being an outage
# ---------------------------------------------------------------------------


def test_an_unprobed_upstream_still_serves_its_tools() -> None:
    """Unknown means ask. Withdrawing on ignorance would mean a monitor that
    failed to start produces a gateway that serves nothing."""
    assert HealthRecord("mock-a").serves_tools is True
    assert HealthRecord("mock-a").state is UpstreamHealth.UNKNOWN


def test_an_upstream_nobody_configured_reads_as_unknown() -> None:
    assert monitor().record_for("never-heard-of-it").state is UpstreamHealth.UNKNOWN


def test_only_a_failed_probe_withdraws_anything() -> None:
    assert HealthRecord("a", UpstreamHealth.HEALTHY).serves_tools is True
    assert HealthRecord("a", UpstreamHealth.UNHEALTHY).serves_tools is False


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


def test_a_successful_probe_records_the_tool_count() -> None:
    """The count is the useful part: an upstream answering with zero tools is
    reachable but useless, and that is worth being able to see."""
    up = FakeUpstream("mock-a", [tool("search"), tool("read")])
    m = monitor(up)

    run(m.probe_once)

    record = m.record_for("mock-a")
    assert record.state is UpstreamHealth.HEALTHY
    assert record.tool_count == 2
    assert record.error is None


def test_a_failed_probe_records_the_error_type_only() -> None:
    """The type is reportable on an unauthenticated endpoint; the message is
    not — it quotes hosts, arguments and upstream responses."""
    up = FakeUpstream(
        "mock-a", UpstreamUnavailableError("cannot reach 10.1.2.3", upstream="mock-a")
    )
    m = monitor(up)

    run(m.probe_once)

    record = m.record_for("mock-a")
    assert record.state is UpstreamHealth.UNHEALTHY
    assert record.error == "UpstreamUnavailableError"
    assert "10.1.2.3" not in str(record.as_dict())


def test_every_upstream_is_probed_concurrently() -> None:
    """One unreachable upstream taking its full connect timeout must not delay
    finding out about the others — same reasoning as the catalogue fan-out."""
    slow = FakeUpstream("slow", UpstreamTimeoutError("slow", upstream="slow"))
    fast = FakeUpstream("fast", [tool("search")])
    m = monitor(slow, fast)

    run(m.probe_once)

    assert slow.probes == 1
    assert fast.probes == 1


def test_one_upstream_failing_does_not_stop_the_others_being_recorded() -> None:
    bad = FakeUpstream("bad", UpstreamUnavailableError("down", upstream="bad"))
    good = FakeUpstream("good", [tool("search")])
    m = monitor(bad, good)

    run(m.probe_once)

    assert m.record_for("good").state is UpstreamHealth.HEALTHY
    assert m.record_for("bad").state is UpstreamHealth.UNHEALTHY


def test_a_gateway_bug_in_a_probe_does_not_kill_the_monitor() -> None:
    """A prober that dies takes every other upstream's monitoring with it. A
    non-taxonomy exception is a bug worth logging loudly, not worth silence and
    not worth the loop."""
    broken = FakeUpstream("broken", ZeroDivisionError())
    other = FakeUpstream("other", [tool("search")])
    m = monitor(broken, other)

    run(m.probe_once)

    assert m.record_for("broken").state is UpstreamHealth.UNHEALTHY
    assert m.record_for("other").state is UpstreamHealth.HEALTHY


def test_recovery_is_detected_without_any_traffic() -> None:
    """The reason this module exists.

    A breaker that opened will not half-open until somebody calls. With no
    traffic there is nobody, so a gateway that goes quiet overnight would wake
    with every circuit still open. The prober is that somebody.
    """
    up = FakeUpstream("mock-a", UpstreamUnavailableError("down", upstream="mock-a"))
    m = monitor(up)

    run(m.probe_once)
    assert m.serves_tools("mock-a") is False

    up.outcome = [tool("search")]
    run(m.probe_once)

    assert m.serves_tools("mock-a") is True


# ---------------------------------------------------------------------------
# What it says out loud
# ---------------------------------------------------------------------------


def test_only_transitions_are_logged(caplog: pytest.LogCaptureFixture) -> None:
    """A probe every fifteen seconds forever would otherwise be a log line
    every fifteen seconds forever — the same mistake as logging every scrape."""
    up = FakeUpstream("mock-a", [tool("search")])
    m = monitor(up)

    with caplog.at_level(logging.WARNING, logger="acp.health"):
        run(m.probe_once)
        run(m.probe_once)
        run(m.probe_once)

    changes = [r for r in caplog.records if r.getMessage() == "health.changed"]
    assert len(changes) == 1


def test_a_change_back_is_also_a_transition(caplog: pytest.LogCaptureFixture) -> None:
    up = FakeUpstream("mock-a", [tool("search")])
    m = monitor(up)

    with caplog.at_level(logging.WARNING, logger="acp.health"):
        run(m.probe_once)
        up.outcome = UpstreamUnavailableError("down", upstream="mock-a")
        run(m.probe_once)
        up.outcome = [tool("search")]
        run(m.probe_once)

    changes = [r for r in caplog.records if r.getMessage() == "health.changed"]
    assert len(changes) == 3


def test_withdrawn_reports_what_is_being_held_back() -> None:
    up = FakeUpstream("mock-a", UpstreamTimeoutError("slow", upstream="mock-a"))
    m = monitor(up, FakeUpstream("mock-b", [tool("chat")]))

    run(m.probe_once)

    assert dict(m.withdrawn()) == {"mock-a": "UpstreamTimeoutError"}


# ---------------------------------------------------------------------------
# Serving nothing
# ---------------------------------------------------------------------------


def test_serving_nothing_when_every_upstream_is_down() -> None:
    m = monitor(
        FakeUpstream("a", UpstreamUnavailableError("down", upstream="a")),
        FakeUpstream("b", UpstreamUnavailableError("down", upstream="b")),
    )

    run(m.probe_once)

    assert m.is_serving_nothing is True


def test_one_healthy_upstream_is_not_serving_nothing() -> None:
    """Partial service is service. The whole partial-failure policy rests on
    this not being treated as an outage."""
    m = monitor(
        FakeUpstream("a", UpstreamUnavailableError("down", upstream="a")),
        FakeUpstream("b", [tool("chat")]),
    )

    run(m.probe_once)

    assert m.is_serving_nothing is False


def test_no_upstreams_configured_is_not_an_outage() -> None:
    """A gateway with nothing attached is a legitimate way to bring one up —
    the same distinction `Catalogue.is_total_failure` draws."""
    assert monitor().is_serving_nothing is False


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def test_the_interval_is_jittered() -> None:
    """Every replica probing on the same tick is a synchronised burst against
    every upstream, from the component whose entire purpose is avoiding exactly
    that — the same reasoning as the retry backoff."""
    seen: list[tuple[float, float]] = []

    def fake_uniform(low: float, high: float) -> float:
        seen.append((low, high))
        return low

    m = monitor(interval=10.0, jitter=0.3, uniform=fake_uniform)
    m._next_delay()

    assert seen == [(7.0, 13.0)]


def test_the_delay_is_never_negative() -> None:
    """A jitter setting above 1 would otherwise produce a negative sleep."""
    m = monitor(interval=1.0, jitter=5.0, uniform=lambda low, _high: low)

    assert m._next_delay() >= 0.0


def test_the_loop_probes_before_it_first_sleeps() -> None:
    """A gateway that has just started knows nothing. Waiting one interval to
    find out is one interval of serving a catalogue nobody has checked."""
    up = FakeUpstream("mock-a", [tool("search")])
    m = monitor(up, interval=0.01)
    sleeps = 0

    class EnoughError(Exception):
        """Ends the loop. Not `StopIteration`, which a coroutine converts into
        a `RuntimeError` and which would make this test pass for the wrong
        reason."""

    async def counting_sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 2:
            raise EnoughError

    async def _run() -> None:
        with pytest.raises(EnoughError):
            await m.run(sleep=counting_sleep)

    run(_run)

    assert up.probes == 2, "probed, slept, probed — not slept, probed"


def test_an_open_circuit_does_not_overwrite_the_real_cause() -> None:
    """The gateway refusing to call is not news about the upstream.

    Once the breaker opens, every probe fails with `UpstreamCircuitOpenError`.
    Recording that would mean `/readyz` reports "we have stopped trying" a few
    seconds into an outage, having quietly discarded "we cannot connect" — the
    one fact an operator actually needs. Same distinction `counts_as_failure`
    draws inside the breaker itself.
    """
    up = FakeUpstream("mock-a", UpstreamUnavailableError("refused", upstream="mock-a"))
    m = monitor(up)

    run(m.probe_once)
    assert m.record_for("mock-a").error == "UpstreamUnavailableError"

    up.outcome = UpstreamCircuitOpenError(
        "circuit open", upstream="mock-a", retry_after_seconds=22.0
    )
    run(m.probe_once)

    assert m.record_for("mock-a").state is UpstreamHealth.UNHEALTHY
    assert m.record_for("mock-a").error == "UpstreamUnavailableError", (
        "the breaker's refusal replaced the reason the breaker opened"
    )


def test_an_open_circuit_with_no_known_cause_reports_itself() -> None:
    """A gateway that started with the circuit already open has no earlier
    cause to preserve, and saying nothing would be worse than saying this."""
    up = FakeUpstream(
        "mock-a", UpstreamCircuitOpenError("open", upstream="mock-a", retry_after_seconds=5.0)
    )
    m = monitor(up)

    run(m.probe_once)

    assert m.record_for("mock-a").error == "UpstreamCircuitOpenError"
