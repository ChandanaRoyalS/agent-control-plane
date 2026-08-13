"""The load harness's decisions, tested — task 60.

A load generator is a measuring instrument, and **an instrument nobody
calibrated produces numbers with the authority of measurement and the content
of a guess.** The classifier is the part that can be wrong silently: misread
one response shape and a run reports an error rate manufactured entirely by the
harness, which looks exactly like a finding about the gateway.

So the wiring lives in `perf/locustfile.py` and everything here is reachable
without Locust installed.
"""

from __future__ import annotations

import json

import pytest
from perf.scenarios import (
    MIX,
    PRINCIPALS,
    PROTOCOL_VERSION,
    UNIQUE_MARKER,
    UPSTREAM_ERRORS,
    WARMUP_SECONDS,
    Call,
    Outcome,
    after_warmup,
    classify,
    percentiles,
    principal_for,
)

TOKEN = "not-a-real-token"


def rpc(payload: dict[str, object]) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": 1, **payload})


def sse(payload: dict[str, object]) -> str:
    return f"event: message\ndata: {rpc(payload)}\n\n"


# ---------------------------------------------------------------------------
# The request a real client sends
# ---------------------------------------------------------------------------


def test_a_tool_call_carries_both_routing_headers() -> None:
    """The bug this guards against is silent and expensive.

    The pre-dispatch fast path abstains when `Mcp-Name` is missing (ADR 0043),
    so a harness that omitted it would benchmark the slow route while
    publishing the numbers as though they described the fast one. Task 55 found
    this exact omission in the test suite.
    """
    call = next(c for c in MIX if c.method == "tools/call")
    headers = call.headers(TOKEN)
    assert headers["Mcp-Method"] == "tools/call"
    assert headers["Mcp-Name"] == call.tool
    assert headers["MCP-Protocol-Version"] == PROTOCOL_VERSION


def test_tools_list_carries_no_name_header() -> None:
    """`tools/list` names no tool, and inventing one would make the gateway
    authorize a call nobody made."""
    call = next(c for c in MIX if c.method == "tools/list")
    assert "Mcp-Name" not in call.headers(TOKEN)


def test_the_body_carries_the_envelope() -> None:
    """The revision requires it and the gateway checks it against the headers
    (ADR 0008). A body without it is a request shape no real client sends."""
    body = MIX[0].body()
    params = body["params"]
    assert isinstance(params, dict)
    meta = params["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == PROTOCOL_VERSION
    assert "io.modelcontextprotocol/clientCapabilities" in meta


def test_every_call_in_the_mix_says_why_it_is_there() -> None:
    """A task mix is a claim about what real traffic looks like. An entry with
    no stated reason is one nobody can argue with, which means nobody can fix
    it either."""
    for call in MIX:
        assert call.why.strip(), f"{call.name} has no rationale"
        assert call.weight > 0


def test_the_mix_covers_both_cache_paths() -> None:
    """A run that only ever hits or only ever misses reports one path's latency
    as though it were the gateway's."""
    queries = [c.arguments.get("query") for c in MIX if c.arguments and "query" in c.arguments]
    assert UNIQUE_MARKER in queries, "no cache-missing call in the mix"
    assert any(q != UNIQUE_MARKER for q in queries), "no cache-hitting call in the mix"


# ---------------------------------------------------------------------------
# Classification — the part that is wrong silently
# ---------------------------------------------------------------------------


def test_a_served_result_is_served() -> None:
    assert classify(200, rpc({"result": {"content": [{"type": "text", "text": "hi"}]}})) is (
        Outcome.SERVED
    )


def test_a_catalogue_is_its_own_outcome() -> None:
    """It never touches the cache or the firewall, so its latency is a
    different population and must not be averaged with tool calls."""
    assert classify(200, rpc({"result": {"tools": []}})) is Outcome.LISTED


def test_a_held_call_is_not_an_error() -> None:
    """`input_required` is the approval flow working. Scoring it as a failure
    would make the error rate rise the moment somebody gates a tool."""
    assert classify(200, rpc({"result": {"resultType": "input_required"}})) is Outcome.HELD


def test_a_pre_dispatch_refusal_is_an_http_403_with_no_rpc_body() -> None:
    """The fast path refuses before a body is parsed (ADR 0043), so there is no
    JSON-RPC frame to read. A classifier that only looked inside the body would
    score the fastest, most common refusal as a transport failure."""
    assert classify(403, '{"error": "forbidden"}') is Outcome.REFUSED
    assert classify(403, "") is Outcome.REFUSED


def test_a_handler_level_denial_is_also_a_refusal() -> None:
    """Same decision, different layer, same bucket — otherwise the report
    changes shape depending on which layer happened to refuse."""
    assert classify(200, rpc({"error": {"code": -32040, "message": "no"}})) is Outcome.REFUSED


@pytest.mark.parametrize("code", [-32050, -32051])
def test_rate_limits_and_quotas_are_throttled_not_refused(code: int) -> None:
    """Separated because they mean different things to a reader: a refusal is
    about entitlement, a throttle means **this run measured the limiter** and
    the latency numbers describe a queue rather than a gateway."""
    assert classify(200, rpc({"error": {"code": code, "message": "slow down"}})) is (
        Outcome.THROTTLED
    )


def test_an_unrecordable_call_has_its_own_bucket() -> None:
    """Fail-closed means the call did not happen (ADR 0050). Under load this is
    the one to watch, because fsync-per-entry bounds throughput to the disk."""
    assert classify(200, rpc({"error": {"code": -32060, "message": "?"}})) is Outcome.UNRECORDED


@pytest.mark.parametrize("code", [-32010, -32011, -32012, -32017, -32018])
def test_an_upstream_failure_is_not_a_gateway_defect(code: int) -> None:
    """The bucket the first 20-user run earned.

    An upstream timeout under load is the gateway *correctly reporting* that a
    mock could not keep up. Counting it as a defect points the reader at the
    wrong component — and "the only bucket that should be zero" stops being
    true the moment you push hard enough to make an upstream slow. What it
    really means is that the run measured the mock fleet as much as the
    gateway.
    """
    assert classify(200, rpc({"error": {"code": code, "message": "upstream"}})) is Outcome.UPSTREAM


def test_an_unexpected_error_code_is_still_a_defect() -> None:
    """Unknown means unknown. Quietly bucketing a novel error as "the gateway
    working" is how a real regression gets absorbed into a healthy-looking
    report — so the upstream family is enumerated, not guessed at by sign."""
    assert -32099 not in UPSTREAM_ERRORS
    assert classify(200, rpc({"error": {"code": -32099, "message": "?"}})) is Outcome.FAILED


def test_the_upstream_family_does_not_swallow_its_neighbours() -> None:
    """-32040 (policy), -32050/-32051 (budget) and -32060 (audit) sit just
    outside the range and mean entirely different things."""
    for code in (-32040, -32050, -32051, -32060):
        assert code not in UPSTREAM_ERRORS


def test_a_server_error_is_a_defect() -> None:
    assert classify(500, "") is Outcome.FAILED
    assert classify(0, "") is Outcome.FAILED


def test_a_401_is_the_harness_misconfigured() -> None:
    """Counted as a defect on purpose. A load run against a gateway that
    refuses every request would otherwise report a beautiful p99."""
    assert classify(401, "") is Outcome.FAILED


def test_an_sse_framed_response_reads_the_same_as_json() -> None:
    """The gateway may answer either way. A harness that parsed only one would
    manufacture an error rate — the most expensive kind of wrong number,
    because it looks like a finding."""
    assert classify(200, sse({"result": {"content": []}})) is Outcome.SERVED
    assert classify(200, sse({"error": {"code": -32040}})) is Outcome.REFUSED


def test_an_unparseable_body_is_a_defect_not_a_crash() -> None:
    for body in ("", "   ", "not json", "{", "event: ping\n\n"):
        assert classify(200, body) is Outcome.FAILED


def test_a_result_that_is_neither_shape_is_a_defect() -> None:
    """A 200 with a `result` naming nothing recognisable is a protocol change
    or a bug, and either way it is not a served call."""
    assert classify(200, rpc({"result": {"unexpected": True}})) is Outcome.FAILED


# ---------------------------------------------------------------------------
# Percentiles
# ---------------------------------------------------------------------------


def test_percentiles_are_real_observations() -> None:
    """Nearest-rank, so no reported latency is one that nobody experienced.

    An interpolated p99 is a weighted average of two samples — a plausible
    number that never happened, in a report whose entire purpose is to say what
    did.
    """
    samples = [float(n) for n in range(1, 101)]
    assert percentiles(samples) == {50: 50.0, 95: 95.0, 99: 99.0}
    for value in percentiles(samples).values():
        assert value in samples


def test_percentiles_of_one_sample() -> None:
    assert percentiles([7.0]) == {50: 7.0, 95: 7.0, 99: 7.0}


def test_an_empty_bucket_has_no_percentiles() -> None:
    """Not zeros. A bucket with no requests has no p95, and `0.0` would read as
    "very fast" in exactly the report where that matters most."""
    assert percentiles([]) == {}


def test_percentiles_do_not_care_about_input_order() -> None:
    assert percentiles([9.0, 1.0, 5.0]) == percentiles([1.0, 5.0, 9.0])


def test_a_call_is_frozen() -> None:
    """The mix is shared across Locust's workers; a mutable entry would let one
    worker's request rewrite another's."""
    with pytest.raises(AttributeError):
        MIX[0].weight = 99  # type: ignore[misc]


def test_unique_calls_get_a_marker_a_reader_can_find() -> None:
    call = Call(
        name="x", method="tools/call", tool="t", arguments={"q": UNIQUE_MARKER}, weight=1, why="x"
    )
    assert UNIQUE_MARKER in json.dumps(call.body())


# ---------------------------------------------------------------------------
# Spreading the run across principals — the bug the first run shipped with
# ---------------------------------------------------------------------------


def test_principals_actually_alternate() -> None:
    """The regression test for a harness bug that produced a full, confident,
    single-identity report.

    v1 chose the user with `id(self) % 2`. CPython object addresses are
    16-byte aligned, so that expression is 0 for **every object ever
    allocated** — every simulated user became alice, and nothing errored.
    """
    chosen = [principal_for(i) for i in range(10)]
    assert set(chosen) == set(PRINCIPALS), "the run never leaves one principal"
    assert chosen[0] != chosen[1]


def test_principals_are_evenly_spread() -> None:
    """Uneven spread would bias the cache hit rate toward whichever principal
    got more users, which is the number the mix exists to make honest."""
    chosen = [principal_for(i) for i in range(100)]
    for user in PRINCIPALS:
        assert chosen.count(user) == 100 // len(PRINCIPALS)


def test_the_id_based_version_would_have_failed_this() -> None:
    """A regression test proves nothing until you show it would have caught the
    thing (lesson 25). This is the original expression, asserted broken."""

    class Simulated:
        pass

    ids = [id(Simulated()) for _ in range(20)]
    assert all(i % 2 == 0 for i in ids), "if this ever fails, the original bug was luck"


# ---------------------------------------------------------------------------
# Warm-up
# ---------------------------------------------------------------------------


def test_warmup_samples_are_discarded() -> None:
    """Cold pools, cold JWKS and cold caches are real costs and are not the
    steady-state latency the report claims to describe. At 30 seconds they land
    squarely in the p99, which is the number people quote."""
    samples = [(0.5, 500.0), (1.0, 400.0), (5.0, 10.0), (6.0, 12.0)]
    assert after_warmup(samples, warmup_seconds=3.0) == [10.0, 12.0]


def test_a_run_shorter_than_the_warmup_reports_what_it_has() -> None:
    """An empty table reads as "no requests". The request count is printed
    beside it, so a reader can judge — but they must be given something to
    judge."""
    samples = [(0.1, 50.0), (0.2, 60.0)]
    assert after_warmup(samples, warmup_seconds=3.0) == [50.0, 60.0]


def test_the_default_warmup_window_is_declared() -> None:
    """A discarded window nobody can see is a number quietly improved."""
    assert WARMUP_SECONDS > 0
    samples = [(WARMUP_SECONDS - 0.1, 999.0), (WARMUP_SECONDS + 0.1, 1.0)]
    assert after_warmup(samples) == [1.0]
