"""Unit tests for metrics.

The cardinality rules carry the weight here. Every other property of a metric
degrades gracefully when it is wrong — a mislabelled counter is merely confusing.
An unbounded label is different in kind: it consumes memory in the metrics
server permanently, for every distinct value it ever sees, and the component
that falls over is the one you were relying on to tell you what was wrong.

Written to pass whether or not `prometheus_client` is installed, for the same
reason the tracing tests are: the recording calls are unconditional at their
call sites, so the no-op path has to be correct or turning metrics off would
break the gateway rather than quieten it.
"""

from __future__ import annotations

import pytest

from acp.observability import metrics

# ---------------------------------------------------------------------------
# Label hygiene — the rules that keep this from becoming a liability
# ---------------------------------------------------------------------------


def test_a_known_tool_keeps_its_name() -> None:
    assert metrics.tool_label("search", {"search", "read_document"}) == "search"


def test_an_unknown_tool_collapses_to_one_label() -> None:
    """The cardinality guard, and the reason it exists.

    The tool name in a `tools/call` is chosen by the agent, not by us. Without
    this, an agent calling a hundred thousand nonexistent tools mints a hundred
    thousand permanent time series — a memory write into someone else's process,
    repeatable as fast as requests can be issued.
    """
    assert metrics.tool_label("../../etc/passwd", {"search"}) == metrics.UNKNOWN_TOOL
    assert metrics.tool_label("a" * 5000, {"search"}) == metrics.UNKNOWN_TOOL


def test_every_unknown_tool_maps_to_the_same_value() -> None:
    """One series for all of them, not one each — otherwise the guard would
    only rename the problem."""
    unknown = {metrics.tool_label(f"tool-{i}", {"search"}) for i in range(1000)}

    assert unknown == {metrics.UNKNOWN_TOOL}


def test_an_absent_tool_is_its_own_bounded_value() -> None:
    """`tools/list` runs no tool. That is a legitimate, bounded label value and
    lumping it in with `unknown` would confuse a healthy catalogue fetch with a
    call to something that does not exist."""
    assert metrics.tool_label(None) == "none"
    assert metrics.tool_label(None) != metrics.UNKNOWN_TOOL


def test_skipping_the_check_is_possible_but_explicit() -> None:
    """Correct only where the name was already resolved against a catalogue —
    which is why it takes an explicit `None` rather than being the default."""
    assert metrics.tool_label("already-resolved") == "already-resolved"


# ---------------------------------------------------------------------------
# Bucket choice
# ---------------------------------------------------------------------------


def test_the_buckets_reach_past_the_read_timeout() -> None:
    """Prometheus' defaults stop at 10 seconds and the default read timeout is
    30, so every timed-out call would land in the overflow bucket together — and
    a p99 computed from a bucket with no upper bound is a guess, not a number.
    The tail is where the interesting failures are."""
    assert max(metrics.DURATION_BUCKETS) >= 60.0
    assert 30.0 in metrics.DURATION_BUCKETS


def test_the_buckets_resolve_fast_calls_too() -> None:
    """An in-datacentre tool call is single-digit milliseconds. Without a bucket
    below that, every healthy call looks identical."""
    assert min(metrics.DURATION_BUCKETS) <= 0.005


def test_the_buckets_are_ascending() -> None:
    assert list(metrics.DURATION_BUCKETS) == sorted(metrics.DURATION_BUCKETS)


# ---------------------------------------------------------------------------
# Breaker state as a state set
# ---------------------------------------------------------------------------


def test_every_breaker_state_is_exported() -> None:
    """A state missing from this tuple would silently never be published, so a
    dashboard would show a breaker that never entered it."""
    from acp.upstream.breaker import BreakerState  # noqa: PLC0415

    assert set(metrics.BREAKER_STATES) == {str(s) for s in BreakerState}


# ---------------------------------------------------------------------------
# The no-op path
# ---------------------------------------------------------------------------


def test_recording_works_without_the_library_installed() -> None:
    """These call sites are unconditional. If they raised when metrics were
    unavailable, an optional dependency would become a required one — and it
    would fail on the request path rather than at startup."""
    metrics.record_upstream_call(
        upstream="mock-a", method="tools/call", tool="search", outcome="ok", duration_seconds=0.01
    )
    metrics.record_retry(upstream="mock-a", method="tools/list")
    metrics.observe_breaker(upstream="mock-a", state="open")
    metrics.observe_bulkhead(upstream="mock-a", in_flight=2, capacity=20)
    metrics.record_credential_cache(outcome="hit")
    metrics.record_result_cache(outcome="hit")


def test_rendering_always_returns_a_body_and_a_content_type() -> None:
    """`/metrics` must answer honestly rather than 500 — a scrape failing looks
    like the gateway is broken when it is only uninstrumented."""
    payload, content_type = metrics.render()

    assert isinstance(payload, bytes)
    assert "text/plain" in content_type


@pytest.mark.skipif(not metrics.METRICS_AVAILABLE, reason="prometheus_client not installed")
def test_recorded_values_reach_the_exposition() -> None:
    """End to end where the library exists: a recorded call appears in a scrape,
    with the namespace and the `_total` suffix Prometheus convention expects."""
    metrics.record_upstream_call(
        upstream="metrics-test",
        method="tools/call",
        tool="search",
        outcome="ok",
        duration_seconds=0.02,
    )

    body = metrics.render()[0].decode()

    assert "acp_upstream_calls_total" in body
    assert 'upstream="metrics-test"' in body
    assert "acp_upstream_call_duration_seconds_bucket" in body


@pytest.mark.skipif(not metrics.METRICS_AVAILABLE, reason="prometheus_client not installed")
def test_the_credential_cache_counter_is_labelled_by_outcome_and_nothing_else() -> None:
    """Hits and misses are the whole signal, and `outcome` is the whole label.

    The tempting extra label is the principal or the upstream audience, so a
    scrape could show whose credentials are churning. Both are unbounded — a
    Prometheus label is a time series per distinct value, and one derived from a
    credential is also a credential-shaped string sitting in a scrape endpoint
    that ADR 0010 already treats as a reconnaissance report.
    """
    metrics.record_credential_cache(outcome="hit")
    metrics.record_credential_cache(outcome="miss")

    body = metrics.render()[0].decode()
    lines = [line for line in body.splitlines() if line.startswith("acp_credential_cache_total{")]

    assert lines, "the counter never reached the exposition"
    assert all(line.count("=") == 1 for line in lines), f"an extra label appeared: {lines}"
    assert any('outcome="hit"' in line for line in lines)
    assert any('outcome="miss"' in line for line in lines)


@pytest.mark.skipif(not metrics.METRICS_AVAILABLE, reason="prometheus_client not installed")
def test_the_breaker_state_set_has_exactly_one_live_state() -> None:
    """The defining property of a state set. Two states reading 1 at once means
    a transition published half of itself."""
    metrics.observe_breaker(upstream="state-test", state="open")

    body = metrics.render()[0].decode()
    live = [
        line
        for line in body.splitlines()
        if 'upstream="state-test"' in line and line.rstrip().endswith("1.0")
    ]

    assert len(live) == 1
    assert 'state="open"' in live[0]
