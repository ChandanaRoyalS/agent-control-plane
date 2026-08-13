"""Gateway overhead: the request shapes, the feature register and the
arithmetic — task 62.

The driver cannot be unit tested; these can, and they are the parts that would
be **silently wrong**. A direct request that asked a different question than the
gateway request would produce an overhead figure comparing two unrelated calls,
and nothing would error. A cache-hit row run against a gateway with no cache
would print a plausible table in which the cache saves nothing, and nothing
would error there either.

Both are tested here because both produce a *number somebody quotes*.
"""

from __future__ import annotations

import itertools
import json

import pytest
from perf.overhead import (
    ABLATION,
    ALWAYS_ON,
    BACKGROUND,
    DIRECT,
    FEATURES,
    MEASURED,
    Measurement,
    Overhead,
    Step,
    applicable,
    attributable,
    classify_step,
    compare,
    decode,
    direct_request,
    encode,
    features,
    flags,
    ladder,
    parse_env,
    resolution,
    spread,
    uniquify,
    unqualified,
)
from perf.scenarios import MIX, PROTOCOL_VERSION, Call

FULL = {
    "ACP_AUTH_REQUIRED": "true",
    "ACP_AUTH_CLIENT_ID": "acp-gateway",
    "ACP_CACHE_FILE": "/app/config/cache.yaml",
    "ACP_COST_FILE": "/app/config/costs.yaml",
    "ACP_RATE_LIMIT_ENABLED": "true",
    "ACP_QUOTA_ENABLED": "true",
    "ACP_FIREWALL_MODE": "report",
    "ACP_PROVENANCE_FRAMING_ENABLED": "true",
    "ACP_AUDIT_FSYNC": "true",
    "ACP_HEALTH_PROBING_ENABLED": "true",
    "OTEL_TRACES_EXPORTER": "otlp",
}


def a_call(tool: str = "mock-a__search") -> Call:
    return Call(
        name="x", method="tools/call", tool=tool, arguments={"query": "q"}, weight=1, why="test"
    )


# ---------------------------------------------------------------------------
# The request shapes
# ---------------------------------------------------------------------------


def test_the_qualified_name_is_split_for_the_upstream() -> None:
    """The gateway namespaces every tool by upstream (ADR 0003) so two
    upstreams can both have a `search`. The upstream itself knows no such
    prefix, so asking it `mock-a__search` would ask for a tool it does not
    have."""
    assert unqualified("mock-a__search") == ("mock-a", "search")
    assert unqualified("mock-b__summarize") == ("mock-b", "summarize")


def test_the_direct_request_asks_the_same_question() -> None:
    """The load-bearing property. Same arguments, same envelope, same protocol
    version — only the name is unqualified and the auth header absent."""
    call = a_call()
    url, body, headers = direct_request(call)

    assert url == DIRECT["mock-a"]
    assert body["params"]["name"] == "search"
    assert body["params"]["arguments"] == call.body()["params"]["arguments"]
    assert body["params"]["_meta"] == call.body()["params"]["_meta"]
    assert headers["Mcp-Name"] == "search"
    assert headers["MCP-Protocol-Version"] == PROTOCOL_VERSION


def test_the_direct_request_carries_no_authorization() -> None:
    """The mock has no auth to offer, and pretending otherwise would understate
    the gateway's cost. Counted as overhead on purpose — see the module."""
    _, _, headers = direct_request(a_call())
    assert "Authorization" not in headers


def test_the_gateway_request_keeps_the_qualified_name() -> None:
    """Both halves of the comparison must be right. The gateway is asked with
    the namespaced name because that is what a real client sends it."""
    call = a_call()
    assert call.body()["params"]["name"] == "mock-a__search"
    assert call.headers("t")["Mcp-Name"] == "mock-a__search"


def test_a_catalogue_call_has_no_direct_equivalent() -> None:
    """`tools/list` fans out to every upstream and merges. There is no single
    server to ask, so an "equivalent" direct call would be a fiction — refused
    rather than approximated."""
    listing = next(c for c in MIX if c.tool is None)
    with pytest.raises(ValueError, match="no meaningful direct equivalent"):
        direct_request(listing)


def test_a_measurement_without_a_tool_refuses_rather_than_reporting_a_row() -> None:
    """The same refusal one layer up, so a mistake is caught where it is made
    rather than printed as a row labelled `?`."""
    listing = next(c for c in MIX if c.tool is None)
    measurement = Measurement(label="bad", call=listing, unique=True, requires=(), why="test")
    with pytest.raises(ValueError, match="no direct equivalent"):
        _ = measurement.tool


def test_every_direct_url_is_reachable_from_the_host() -> None:
    """The gateway reaches the mocks by service name over the compose network;
    a host-side driver cannot. These are the published ports, and a service
    name here would fail to resolve at 3am with a DNS error."""
    for url in DIRECT.values():
        assert url.startswith("http://127.0.0.1:")


# ---------------------------------------------------------------------------
# Forcing a cache miss
# ---------------------------------------------------------------------------


def test_uniquify_does_not_mutate_the_caller() -> None:
    """The body is built once and reused for 180 requests. Mutating it in place
    would make request N+1 depend on request N, and the dependency would be
    invisible — every call would still succeed."""
    body = a_call().body()
    before = body["params"]["arguments"]["query"]
    uniquify(body, 7)
    assert body["params"]["arguments"]["query"] == before


def test_uniquify_changes_the_argument_and_not_the_tool() -> None:
    """The counter goes in the argument because the cache key covers arguments
    (ADR 0035) and policy covers the name. Putting it in the name would miss
    the cache *and* change which rule applies — measuring a different decision
    while reporting it as the same one."""
    body = uniquify(a_call().body(), 7)
    assert body["params"]["arguments"]["query"] == "overhead-7"
    assert body["params"]["name"] == "mock-a__search"


def test_uniquify_is_different_for_every_counter() -> None:
    """The whole point. Two calls that produced the same argument would be a
    cache hit measured as a miss."""
    queries = {uniquify(a_call().body(), n)["params"]["arguments"]["query"] for n in range(50)}
    assert len(queries) == 50


def test_uniquify_leaves_an_argumentless_call_alone() -> None:
    """`tools/list` has no arguments to make unique, and inventing one would
    send a parameter the method does not define."""
    listing = next(c for c in MIX if c.tool is None)
    assert uniquify(listing.body(), 1) == listing.body()


# ---------------------------------------------------------------------------
# The configuration the number cannot be quoted without
# ---------------------------------------------------------------------------


def test_the_environment_splits_on_the_first_equals_only() -> None:
    """Docker's `.Config.Env` is raw `KEY=VALUE` strings and the values here
    legitimately contain `=` — a JSON list of allowed hosts does. Splitting on
    every `=` would silently truncate the value and report a feature as
    configured differently than it is."""
    parsed = parse_env(["A=b", 'ACP_ALLOWED_HOSTS=["a=1","b"]', "MALFORMED"])
    assert parsed["A"] == "b"
    assert parsed["ACP_ALLOWED_HOSTS"] == '["a=1","b"]'
    assert "MALFORMED" not in parsed


def test_an_unset_switch_reads_as_off() -> None:
    """The default for most of these is off, so an absent variable is the
    common case rather than an error case."""
    assert all(not on for _, on in features({}))


def test_a_fully_configured_gateway_reads_as_on() -> None:
    assert all(on for _, on in features(FULL))


@pytest.mark.parametrize("value", ["false", "off", "0", "", "none", "  FALSE  "])
def test_the_spelled_out_ways_of_saying_no_all_read_as_off(value: str) -> None:
    """Three shapes of switch share one predicate — a path, a boolean and an
    enum whose off value is spelled `off`. A per-feature parser would be three
    places for this to be wrong."""
    assert not dict(features({"ACP_FIREWALL_MODE": value}))[
        next(f for f in FEATURES if f.variable == "ACP_FIREWALL_MODE")
    ]


def test_the_register_covers_the_switches_that_change_per_request_work() -> None:
    """A feature built and never added here would be invisible in the report,
    which is exactly the failure this register exists to prevent — and exactly
    what happened once already, when four merged features were inert in the
    only deployment anybody ran because nothing set their variables."""
    variables = {feature.variable for feature in FEATURES}
    assert {
        "ACP_CACHE_FILE",
        "ACP_COST_FILE",
        "ACP_FIREWALL_MODE",
        "ACP_PROVENANCE_FRAMING_ENABLED",
        "ACP_QUOTA_ENABLED",
        "ACP_RATE_LIMIT_ENABLED",
        "ACP_AUDIT_FSYNC",
    } <= variables


def test_background_work_is_a_separate_register() -> None:
    """A different claim from `FEATURES`, and folding them together would let a
    reader conclude the catalogue prober is part of a call's cost. It is not —
    it is part of the machine's cost during the run, and it lands in the tail."""
    assert BACKGROUND
    assert {f.variable for f in BACKGROUND} == {"ACP_HEALTH_PROBING_ENABLED"}
    assert not ({f.variable for f in BACKGROUND} & {f.variable for f in FEATURES})


def test_every_feature_key_is_unique() -> None:
    """The keys are what the one-line form prints. Two features sharing one
    would silently report a single column for both — and the A/B run exists to
    tell those two apart."""
    keys = [f.key for f in (*FEATURES, *BACKGROUND)]
    assert len(keys) == len(set(keys))


def test_the_one_line_form_names_every_switch() -> None:
    """Same source as the long register, so an A/B run's header cannot disagree
    with a single run's."""
    line = flags(FULL)
    for feature in (*FEATURES, *BACKGROUND):
        assert f"{feature.key}=on" in line


def test_the_one_line_form_marks_what_is_off() -> None:
    """`OFF` in capitals on purpose: this line is read four times in a row and
    the difference between runs is the entire point of reading it."""
    assert "fsync=OFF" in flags({**FULL, "ACP_AUDIT_FSYNC": "false"})
    assert "probing=OFF" in flags({**FULL, "ACP_HEALTH_PROBING_ENABLED": "false"})


def test_the_unswitchable_work_is_named_too() -> None:
    """A reader shown only the switch register would conclude that a gateway
    with everything off does nothing. It still refuses calls and still records
    them, and those are in every number reported."""
    assert ALWAYS_ON
    assert any("policy" in item for item in ALWAYS_ON)
    assert any("audit" in item for item in ALWAYS_ON)


# ---------------------------------------------------------------------------
# Refusing to measure something else
# ---------------------------------------------------------------------------


def test_the_cache_row_is_skipped_when_the_gateway_has_no_cache() -> None:
    """THE POINT OF THE REGISTER. Run anyway, this row would print a plausible
    table showing the cache saving nothing — and the true finding, that the
    cache was never switched on, would be absent from the output and from
    whatever ADR quoted it."""
    runnable, skipped = applicable({"ACP_AUTH_REQUIRED": "true"})

    assert [m.label for m in runnable] == ["cache miss"]
    assert [m.label for m, _ in skipped] == ["cache hit"]
    assert "ACP_CACHE_FILE" in skipped[0][1]


def test_both_rows_run_against_a_fully_configured_gateway() -> None:
    runnable, skipped = applicable(FULL)
    assert len(runnable) == len(MEASURED)
    assert not skipped


def test_a_row_with_no_requirements_is_never_skipped() -> None:
    """The cache-miss row measures the full path and needs nothing switched on
    to mean what it says, so an empty stack still produces the headline
    number."""
    runnable, _ = applicable({})
    assert any(m.label == "cache miss" for m in runnable)


def test_the_cache_row_declares_the_switch_it_depends_on() -> None:
    """Asserted directly rather than only through `applicable`, because a
    `requires` quietly emptied would make every `applicable` test above pass
    while removing the guard entirely."""
    row = next(m for m in MEASURED if m.label == "cache hit")
    assert row.requires == ("ACP_CACHE_FILE",)
    assert not row.unique


def test_both_rows_measure_the_same_tool() -> None:
    """Changing the tool between rows would change the *upstream's* work as
    well as the gateway's, and the difference would stop being attributable."""
    assert len({m.tool for m in MEASURED}) == 1


def test_exactly_one_row_forces_a_cache_miss() -> None:
    """Two miss rows would be the same measurement twice; two hit rows would
    never exercise the upstream at all."""
    assert sum(1 for m in MEASURED if m.unique) == 1


# ---------------------------------------------------------------------------
# Arithmetic
# ---------------------------------------------------------------------------


def test_added_is_the_difference_per_percentile() -> None:
    result = compare("t", [10.0, 20.0, 30.0], [1.0, 2.0, 3.0])
    assert result.added[50] == pytest.approx(18.0)
    assert result.multiple == pytest.approx(10.0)


def test_a_negative_overhead_is_representable_even_though_it_was_not_observed() -> None:
    """The arithmetic must survive a gateway faster than the thing it fronts,
    because that is the shape against a *slow* upstream even though it is not
    the shape against a mock that answers in microseconds.

    Kept after the measurement refuted the prediction that the cache-hit row
    would show it — the claim was wrong; the code path is still reachable, and
    a reporting path that cannot represent a negative number would silently
    misreport the day it happens."""
    result = compare("t", [2.0], [8.0])
    assert result.added[50] == pytest.approx(-6.0)
    assert result.multiple == pytest.approx(0.25)


def test_samples_is_the_smaller_of_the_two() -> None:
    """Reporting the larger would claim confidence the thinner side does not
    support."""
    assert compare("t", [1.0] * 10, [1.0] * 7).samples == 7


def test_a_zero_direct_median_does_not_divide_by_zero() -> None:
    """A mock fast enough to round to zero is a plausible future, and a
    ZeroDivisionError in a reporting path is a report nobody gets."""
    assert compare("t", [5.0], [0.0]).multiple == float("inf")


def test_spread_shows_the_range_not_just_the_mean() -> None:
    """Task 61's lesson, in the formatter: a single number hides that one run
    understated by 30%."""
    assert spread([10.0, 20.0, 30.0]) == "20.0 [10.0-30.0]"
    assert spread([]) == "—"


def test_overhead_is_frozen() -> None:
    result = compare("t", [1.0], [1.0])
    with pytest.raises(AttributeError):
        result.tool = "other"  # type: ignore[misc]


def test_an_overhead_reports_both_distributions() -> None:
    """Publishing only the delta would leave a reader unable to tell 2ms added
    to 1ms from 2ms added to 200ms, which are different systems."""
    result: Overhead = compare("t", [10.0], [4.0])
    assert result.gateway[50] == 10.0
    assert result.direct[50] == 4.0


# ---------------------------------------------------------------------------
# The ablation ladder
# ---------------------------------------------------------------------------


def test_the_ladder_accumulates_every_earlier_switch() -> None:
    """THE LOAD-BEARING PROPERTY. A rung that dropped an earlier switch would
    be measured under a configuration other than the one it is labelled with —
    and every row below it too. Nothing would error and the table would look
    exactly as expected."""
    steps = ladder()
    for index, (_, environment) in enumerate(steps):
        for earlier, _ in steps[: index + 1]:
            for name, value in earlier.switch.items():
                assert environment[name] == value


def test_each_rung_environment_is_a_superset_of_the_one_above() -> None:
    steps = ladder()
    for (_, above), (_, below) in itertools.pairwise(steps):
        assert above.items() <= below.items()


def test_the_first_rung_changes_nothing() -> None:
    """The baseline has to be the stack as somebody would actually run it, or
    every marginal cost below it is measured against a fiction."""
    _, environment = ladder()[0]
    assert environment == {}


def test_every_rung_after_the_first_removes_exactly_one_thing() -> None:
    """Two switches in one rung would make its marginal cost unattributable —
    which is the one thing the whole table exists to avoid."""
    for rung in ABLATION[1:]:
        assert len(rung.switch) == 1
        assert rung.removes, f"{rung.label} does not say what it removes"


def test_every_ablated_switch_is_in_a_register() -> None:
    """A rung switching off something the report never mentions would remove
    work from the measurement and not from the printed configuration."""
    known = {f.variable for f in (*FEATURES, *BACKGROUND)}
    for rung in ABLATION[1:]:
        assert set(rung.switch) <= known, f"{rung.label} switches something unregistered"


def test_the_ladder_does_not_mutate_its_rungs() -> None:
    """`ladder` builds the accumulation; a rung that had been updated in place
    would make a second call return something different from the first."""
    before = [dict(rung.switch) for rung in ABLATION]
    ladder()
    ladder()
    assert [dict(rung.switch) for rung in ABLATION] == before


def test_trace_export_is_in_the_register() -> None:
    """It was not, until the ablation went looking for the residual. The
    register was assembled from `GatewaySettings` and tracing is configured by
    OpenTelemetry's own variables — a register built from one source of truth
    misses everything configured by another."""
    assert "OTEL_TRACES_EXPORTER" in {f.variable for f in FEATURES}


# ---------------------------------------------------------------------------
# Handing a run to the next process
# ---------------------------------------------------------------------------


def test_a_payload_round_trips_with_integer_percentile_keys() -> None:
    """JSON object keys are strings, so a percentile map comes back as
    `{"50": ...}` and `result.gateway[50]` raises `KeyError` — at the moment
    the final table is printed, eight minutes of measurement after the last
    chance to notice."""
    original = compare("mock-a__search", [10.0, 20.0, 30.0], [1.0, 2.0, 3.0])
    payload = json.loads(json.dumps(encode("fsync=on", [("cache miss", original)])))

    line, rows = decode(payload)

    assert line == "fsync=on"
    assert len(rows) == 1
    label, restored = rows[0]
    assert label == "cache miss"
    assert restored.gateway[50] == original.gateway[50]
    assert restored.direct[95] == original.direct[95]
    assert restored.tool == "mock-a__search"
    assert restored.samples == original.samples


def test_a_decoded_row_still_computes_its_own_arithmetic() -> None:
    """`added` and `multiple` are properties, so a row that decoded into the
    wrong shape would fail here rather than print a nonsense delta."""
    original = compare("t", [10.0], [4.0])
    _, rows = decode(json.loads(json.dumps(encode("x", [("cache hit", original)]))))
    assert rows[0][1].added[50] == pytest.approx(6.0)


def test_an_empty_run_encodes_without_rows() -> None:
    """Every row skipped is a real outcome — a gateway with nothing applicable —
    and the payload has to survive it rather than raise in the reporter."""
    line, rows = decode(json.loads(json.dumps(encode("all=OFF", []))))
    assert line == "all=OFF"
    assert rows == ()


# ---------------------------------------------------------------------------
# What the harness can and cannot see
# ---------------------------------------------------------------------------


def test_the_floor_is_the_controls_own_spread() -> None:
    """The control is the same request to the same mock in every configuration.
    Whatever it varies by is variation the harness introduced, because the thing
    being measured did not change."""
    assert resolution([5.2, 5.0, 7.1, 5.6]) == pytest.approx(2.1)


def test_one_control_attributes_nothing() -> None:
    """One measurement of a difference has no error bar. Lesson 56, applied to
    this table rather than to the load test — where it was learned and then not
    carried across."""
    assert resolution([5.2]) == float("inf")
    assert resolution([]) == float("inf")
    assert not attributable(999.0, resolution([5.2]))


def test_a_step_below_the_floor_is_not_attributed() -> None:
    """The case this exists for. The first ablation run produced steps of 1.6,
    1.1 and 0.4 ms against a control that wandered by more than 2 — and printing
    those as small costs would have invited a reader to explain them."""
    floor = resolution([5.2, 5.0, 7.1, 5.6])
    assert not attributable(1.6, floor)
    assert not attributable(0.4, floor)
    assert attributable(5.8, floor)


def test_a_negative_step_below_the_floor_is_just_noise() -> None:
    floor = resolution([5.2, 5.0, 7.1, 5.6])
    assert classify_step(-1.7, floor) is Step.BELOW_FLOOR


def test_a_negative_step_above_the_floor_is_impossible_not_resolved() -> None:
    """THE CASE A FAILING TEST INSISTED ON. The first ablation produced -2.6 ms
    against a floor of 2.1 — larger than the control's wobble, and negative.

    Removing work cannot make a system faster, so this is neither a resolved
    cost nor below the floor. It is evidence that **the floor understated the
    noise in that column**, which is what `resolution` warns it might. A
    two-state answer had to call it one or the other and both were wrong."""
    floor = resolution([5.2, 5.0, 7.1, 5.6])
    assert floor == pytest.approx(2.1)
    assert attributable(-2.6, floor)
    assert classify_step(-2.6, floor) is Step.IMPOSSIBLE


def test_a_real_saving_is_resolved() -> None:
    floor = resolution([5.2, 5.0, 7.1, 5.6])
    assert classify_step(5.8, floor) is Step.RESOLVED
    assert classify_step(101.7, floor) is Step.RESOLVED


def test_a_step_exactly_at_the_floor_is_not_attributed() -> None:
    """Strictly greater, because the boundary case is a step the harness has
    already demonstrated it can produce from nothing."""
    assert not attributable(2.0, resolution([5.0, 7.0]))
    assert attributable(2.01, resolution([5.0, 7.0]))
