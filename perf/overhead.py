"""What the gateway costs, versus calling the upstream yourself.

Task 62. *"Latency added versus a direct upstream call, with stated
methodology. The first question anyone who has run infrastructure will ask
you."*

The pure half, as with `scenarios`: request shapes, the feature register and
the arithmetic here; the driver in `scripts/measure_overhead.py`.

**Why this is measured at concurrency 1, when task 60 measured at 20.**

They answer different questions and the same number cannot serve both. Under
saturation a p50 is dominated by *queueing* — how long a request waits for its
turn — which is a property of the offered load, the mix and the machine. Task
60 wants that, because "what happens when it is busy" is the question.

Overhead is *not* that question. Overhead is **the work the gateway does that
the upstream would not have done**, and the only way to see it is to make sure
nothing is waiting: one request in flight, sequentially, many times. A p50 of
300 ms under saturation and 4 ms unloaded are both true and only the second one
is the gateway's cost.

Measuring overhead under load would produce a large, impressive, meaningless
number — and it is the number a careless benchmark reports.

**Why the configuration is read from the running container.**

Almost every expensive thing the gateway does is *optional*, and most of the
switches default to off (`GatewaySettings`: `firewall_mode` is `OFF`,
`rate_limit_enabled` and `quota_enabled` are `False`, `cache_file` and
`cost_file` are `None`). So "the gateway adds 3 ms" is not a fact about the
gateway. It is a fact about **one gateway, configured one way**, and quoting it
without that configuration is how a benchmark becomes marketing.

`FEATURES` is that configuration, made machine-readable: the driver reads the
running container's actual environment and prints which of these were on. A
number this project publishes cannot be separated from the switch settings that
produced it, because the same run prints both.

It also does real work rather than decorating the output — see `applicable`. A
measurement whose premise is switched off is **skipped and explained**, not
quietly run as something else.

**Why the comparison is fair, and where it is not.**

The direct call goes to the same mock, over the same Docker-published port,
with the same MCP envelope and the same JSON body. The differences are exactly
the gateway's job, and exactly what `FEATURES` enumerates.

**The direct path has no authentication**, because the mock has none to offer.
That is not a flaw in the comparison — it is part of what the gateway adds, and
pretending otherwise would understate the honest number. Stated rather than
hidden.

**One difference is not the gateway's job**: the direct call is one network hop
and the gateway path is two, because the gateway sits between. The extra hop is
loopback inside one Docker network, which is small but not zero, and it is
counted in the overhead here. Separating it would need a null gateway that
forwards without deciding, which is a fair thing to want and is not built.
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from perf.scenarios import MIX as _MIX
from perf.scenarios import PROTOCOL_VERSION, Call, percentiles

GATEWAY: Final = "http://127.0.0.1:8080/mcp"

DIRECT: Final = {
    "mock-a": "http://127.0.0.1:9101/mcp",
    "mock-b": "http://127.0.0.1:9102/mcp",
}
"""The mock upstreams as the *host* reaches them, published by compose.

The gateway reaches them as `mock-a:9101` over the project network; this is the
same server through the other door, which is the only way a host-side driver
can talk to it. One extra hop through Docker's published-port proxy applies to
**both** paths' final leg, so it does not bias the difference.
"""

CONTAINER: Final = "acp-gateway"
"""Whose environment to read. The *running container's*, not `docker compose
config` — an operator can start the stack with a variable set on the command
line (`make load-nofsync` does exactly that), and the file would then describe
a gateway that is not the one being measured."""


# ---------------------------------------------------------------------------
# What the gateway is doing, and whether it was switched on
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Feature:
    """One optional piece of per-request work, and the switch that enables it."""

    key: str
    """A short name for the one-line form the A/B run prints. Explicit rather
    than derived from `name`, because deriving it would make "audit fsync" into
    "audit" and collide with nothing today and with something later."""

    name: str
    variable: str
    adds: str

    def enabled(self, env: Mapping[str, str]) -> bool:
        """Set to anything that is not an explicit "no" counts as on.

        One predicate for three shapes of switch — a path (`ACP_CACHE_FILE`), a
        boolean (`ACP_QUOTA_ENABLED`) and an enum whose off value is spelled
        (`ACP_FIREWALL_MODE=off`) — because the alternative is a per-feature
        parser, and a per-feature parser is three places for this to be wrong.
        """
        value = env.get(self.variable)
        return value is not None and value.strip().lower() not in _OFF


_OFF: Final = frozenset({"", "false", "0", "off", "no", "none"})


FEATURES: Final = (
    Feature(
        key="auth",
        name="authentication",
        variable="ACP_AUTH_REQUIRED",
        adds="signature check against the cached JWKS, claim validation, principal resolution",
    ),
    Feature(
        key="exchange",
        name="credential exchange",
        variable="ACP_AUTH_CLIENT_ID",
        adds="RFC 8693 exchange for an upstream-scoped token — one round trip, then cached",
    ),
    Feature(
        key="cache",
        name="result cache",
        variable="ACP_CACHE_FILE",
        adds="a keyed lookup before dispatch, and a store after it",
    ),
    Feature(
        key="costs",
        name="cost-weighted budget",
        variable="ACP_COST_FILE",
        adds="a per-tool weight on the budget draw instead of a flat 1.0",
    ),
    Feature(
        key="ratelimit",
        name="rate limit",
        variable="ACP_RATE_LIMIT_ENABLED",
        adds="a token-bucket draw per call",
    ),
    Feature(
        key="quota",
        name="quota",
        variable="ACP_QUOTA_ENABLED",
        adds="a windowed counter per principal",
    ),
    Feature(
        key="screening",
        name="injection screening",
        variable="ACP_FIREWALL_MODE",
        adds="every detector run over the whole result body on the way back",
    ),
    Feature(
        key="framing",
        name="provenance framing",
        variable="ACP_PROVENANCE_FRAMING_ENABLED",
        adds="two extra content blocks fencing the result as retrieved data",
    ),
    Feature(
        key="tracing",
        name="trace export",
        variable="OTEL_TRACES_EXPORTER",
        adds="a span per request, batched and shipped over OTLP to the collector",
    ),
    Feature(
        key="fsync",
        name="audit fsync",
        variable="ACP_AUDIT_FSYNC",
        adds="the caller waits for the record to reach the platter (ADR 0050 §8)",
    ),
)
"""The optional work, and what each switch buys. Ordered by where it happens in
a request rather than by importance, so the printed table reads as a path."""


ALWAYS_ON: Final = (
    "the pre-dispatch header check (ADR 0043)",
    "policy evaluation down to the argument",
    "the hash-chained audit write",
)
"""Not switchable, so not in the register — but part of every measured number
and therefore named in the report. A reader who sees only `FEATURES` would
conclude a gateway with everything off does nothing, and it still refuses
calls and still records them."""


BACKGROUND: Final = (
    Feature(
        key="probing",
        name="health probing",
        variable="ACP_HEALTH_PROBING_ENABLED",
        adds=(
            "a catalogue refetch from every upstream every "
            "ACP_HEALTH_PROBE_INTERVAL seconds, on the same event loop"
        ),
    ),
)
"""Work that is **not on the request path and competes with it anyway**.

A separate register because it is a different claim. `FEATURES` says "this
request did this work"; this says "something else was running while it did".
Folding the two together would let a reader conclude the prober is part of a
call's cost, which it is not — it is part of the *machine's* cost during the
run, and it lands in the p99 rather than the p50.

Named here because it is a plausible explanation for a tail, and a plausible
explanation that is not written down becomes a guess repeated confidently.
"""


def flags(env: Mapping[str, str]) -> str:
    """One line of `key=on|OFF`, for a run that prints several configurations.

    The long register is right for a single run and unreadable four times in a
    row. Same source, so the two cannot disagree.
    """
    parts = [
        f"{feature.key}={'on' if feature.enabled(env) else 'OFF'}"
        for feature in (*FEATURES, *BACKGROUND)
    ]
    return " ".join(parts)


def parse_env(entries: Sequence[str]) -> dict[str, str]:
    """`["A=b", "C=d=e"]` into a mapping, splitting once.

    Docker's `.Config.Env` is a list of raw `KEY=VALUE` strings and values
    legitimately contain `=` — a JSON list of allowed hosts does, and so does a
    base64 secret. Splitting on every `=` would truncate them.
    """
    parsed: dict[str, str] = {}
    for entry in entries:
        key, separator, value = entry.partition("=")
        if separator:
            parsed[key] = value
    return parsed


def features(env: Mapping[str, str]) -> tuple[tuple[Feature, bool], ...]:
    """Every optional feature, paired with whether this gateway had it on."""
    return tuple((feature, feature.enabled(env)) for feature in FEATURES)


# ---------------------------------------------------------------------------
# What to measure
# ---------------------------------------------------------------------------


def _from_mix(name: str) -> Call:
    return next(call for call in _MIX if call.name == name)


@dataclass(frozen=True, slots=True)
class Measurement:
    """One row of the comparison: which call, and how it is driven."""

    label: str
    call: Call
    unique: bool
    """Whether to rewrite the first argument uniquely on every request.

    `True` forces a cache miss, so the gateway does the whole job. `False`
    leaves the arguments fixed, so the gateway may serve from memory — which is
    the *point* of that row rather than a flaw in it.
    """

    requires: tuple[str, ...]
    """Switches that must be on for this row to mean what its label says.

    Load-bearing. Without it, "cache hit" measured against a gateway with no
    cache configured is a second copy of the cache-miss row wearing a different
    name, and nothing errors.
    """

    why: str

    @property
    def tool(self) -> str:
        """The qualified tool name, refusing rather than guessing for `tools/list`.

        A catalogue call has no single upstream to compare against, so a
        measurement built around one is a mistake worth raising at the point it
        is made rather than producing a row labelled `?`.
        """
        if self.call.tool is None:
            msg = f"measurement {self.label!r} has no tool, so it has no direct equivalent"
            raise ValueError(msg)
        return self.call.tool


MEASURED: Final = (
    Measurement(
        label="cache miss",
        call=_from_mix("search (unique)"),
        unique=True,
        requires=(),
        why=(
            "the full path: policy, budget, a cache lookup that misses, credential "
            "exchange, a real upstream call, screening and the audit write. This is "
            "the number that answers 'what does the gateway cost me'."
        ),
    ),
    Measurement(
        label="cache hit",
        call=_from_mix("search (repeated)"),
        unique=False,
        requires=("ACP_CACHE_FILE",),
        why=(
            "the same question asked twice, which is common in one agent turn. The "
            "gateway answers from memory and never reaches the upstream, so the "
            "difference between this row and the one above is what the cache is "
            "worth. It is NOT expected to beat the direct call — see the note on "
            "MEASURED — and the first measurement is what corrected that."
        ),
    ),
)
"""The two rows, and why there are exactly two.

Both are `mock-a__search`, deliberately: changing the tool between rows would
change the upstream's own work as well as the gateway's, and the difference
would no longer be attributable. One tool, two cache outcomes, everything else
held still.

**A prediction this file made, and the measurement that refuted it.** The first
version of this docstring said the cache-hit row was "where the overhead goes
negative" — that a call answered from memory would beat one crossing the
network. It does not, and it is not close: measured, the gateway serves a hit in
22.8 ms against a direct upstream call's 6.8 ms.

The reason is arithmetic that should have been done before the claim was
written. A hit removes **the upstream round trip**, which against a mock is
about 6 ms. It removes nothing else: the gateway still authenticates, still
evaluates policy, still screens and frames the result, and still waits for an
audit record to reach the disk. **The gateway's own fixed cost is larger than
the entire thing the cache eliminates**, so the hit is faster than the miss and
slower than going direct.

What the row is actually for, then, is the *difference between the two rows* —
what the cache is worth — which is a real number and a smaller claim than the
one it replaced.

Here rather than in the driver because these are decisions, and decisions in
this project live where a test can reach them.
"""


def applicable(
    env: Mapping[str, str], measurements: Sequence[Measurement] = MEASURED
) -> tuple[tuple[Measurement, ...], tuple[tuple[Measurement, str], ...]]:
    """Split the measurements into the ones this gateway can honestly support.

    Returns `(runnable, skipped)`, where each skip carries the reason.

    This is the guard the rest of the module exists to make possible. A cache
    row run against a gateway with `ACP_CACHE_FILE` unset produces a perfectly
    plausible table in which the cache appears to save nothing — and the true
    finding, *that the cache was never switched on*, would be invisible in the
    output and absent from whatever ADR quoted it.

    **Skipped and explained, rather than run and mislabelled.**
    """
    runnable: list[Measurement] = []
    skipped: list[tuple[Measurement, str]] = []
    for measurement in measurements:
        missing = [
            name for name in measurement.requires if env.get(name, "").strip().lower() in _OFF
        ]
        if missing:
            skipped.append(
                (
                    measurement,
                    f"needs {', '.join(missing)}, which this gateway does not have set",
                )
            )
        else:
            runnable.append(measurement)
    return tuple(runnable), tuple(skipped)


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rung:
    """One step of the ablation: what is switched off, and what that removes."""

    label: str
    removes: str
    switch: dict[str, str]
    """This rung's *own* override only. The cumulative environment is computed
    by `ladder`, so no rung can silently forget to carry an earlier one — which
    is the failure that would make every number below it wrong and none of them
    look it."""


ABLATION: Final = (
    Rung(label="everything on", removes="", switch={}),
    Rung(
        label="- audit fsync",
        removes="the caller waiting for the record to reach the disk",
        switch={"ACP_AUDIT_FSYNC": "false"},
    ),
    Rung(
        label="- health probing",
        removes="a catalogue refetch from every upstream every 5 seconds",
        switch={"ACP_HEALTH_PROBING_ENABLED": "false"},
    ),
    Rung(
        label="- injection screening",
        removes="every detector run over the result body",
        switch={"ACP_FIREWALL_MODE": "off"},
    ),
    Rung(
        label="- provenance framing",
        removes="two content blocks fencing the result as retrieved data",
        switch={"ACP_PROVENANCE_FRAMING_ENABLED": "false"},
    ),
    Rung(
        label="- trace export",
        removes="a span per request, shipped over OTLP",
        switch={"OTEL_TRACES_EXPORTER": "none"},
    ),
    Rung(
        label="- quota",
        removes="a windowed counter read and incremented per call",
        switch={"ACP_QUOTA_ENABLED": "false"},
    ),
    Rung(
        label="- rate limit",
        removes="a token-bucket draw per call",
        switch={"ACP_RATE_LIMIT_ENABLED": "false"},
    ),
)
"""The itemised cost, one switch removed at a time.

**Cumulative, not leave-one-out**, and the difference matters. Each rung keeps
everything the rungs above it removed, so the steps sum to the total and the
last rung is a floor: what remains is authentication, policy, the audit write
without its `fsync`, the framework and the extra hop.

The cost of that choice, stated: **an interaction between two switches is
charged entirely to whichever is removed first.** If screening is only expensive
because framing then copies what it produced, this ladder bills all of it to
screening. Leave-one-out would answer the other question — each feature's
marginal cost in the full configuration — and would not sum to anything.

The order is largest-expected-first, which is a guess made before measuring and
therefore the thing an interaction would most distort. Said out loud rather than
presented as an ordering that fell out of the data.

`- trace export` is last and was not in the register at all until the first
ablation run went looking for what the residual could be. A per-request span
shipped over OTLP is per-request work by any reading; it was missing because the
register was written from `GatewaySettings`, and tracing is configured by
OpenTelemetry's standard variables instead. **A register assembled from one
source of truth misses everything configured by another.**
"""


def ladder(rungs: Sequence[Rung] = ABLATION) -> tuple[tuple[Rung, dict[str, str]], ...]:
    """Each rung paired with the full environment it should run under.

    The accumulation is here, and tested, because doing it in the driver's loop
    is one `dict` copy away from a rung that quietly drops an earlier switch —
    producing a table whose every later row is measured under a configuration
    other than the one it is labelled with, with nothing to show for it.
    """
    accumulated: dict[str, str] = {}
    built: list[tuple[Rung, dict[str, str]]] = []
    for rung in rungs:
        accumulated = {**accumulated, **rung.switch}
        built.append((rung, dict(accumulated)))
    return tuple(built)


# ---------------------------------------------------------------------------
# Handing one run's result to the next process
# ---------------------------------------------------------------------------


def encode(flags_line: str, rows: Sequence[tuple[str, Overhead]]) -> dict[str, Any]:
    """One measurement run, as JSON the ablation driver can read back."""
    return {
        "flags": flags_line,
        "rows": [
            {
                "label": label,
                "tool": result.tool,
                "samples": result.samples,
                "gateway": {str(point): value for point, value in result.gateway.items()},
                "direct": {str(point): value for point, value in result.direct.items()},
            }
            for label, result in rows
        ],
    }


def decode(payload: Mapping[str, Any]) -> tuple[str, tuple[tuple[str, Overhead], ...]]:
    """The inverse, **converting the percentile keys back to integers**.

    That conversion is the whole reason this is a function with a test rather
    than two lines in the driver. JSON object keys are strings, so a percentile
    map round-trips as `{"50": ...}` and `result.gateway[50]` then raises
    `KeyError` — at the moment the final table is printed, which is eight
    minutes of measurement after the last chance to notice.
    """
    rows = tuple(
        (
            str(row["label"]),
            Overhead(
                tool=str(row["tool"]),
                samples=int(row["samples"]),
                gateway={int(point): float(value) for point, value in row["gateway"].items()},
                direct={int(point): float(value) for point, value in row["direct"].items()},
            ),
        )
        for row in payload["rows"]
    )
    return str(payload["flags"]), rows


def unqualified(tool: str) -> tuple[str, str]:
    """Split ``mock-a__search`` into its upstream and the upstream's own name.

    The gateway namespaces every tool by upstream (ADR 0003) precisely so two
    upstreams can both have a `search`. A direct call has no such problem and
    no such prefix — it is talking to one server — so the name has to be taken
    back apart to ask the same question of the same tool.
    """
    upstream, _, name = tool.partition("__")
    return upstream, name


def direct_request(call: Call) -> tuple[str, dict[str, Any], dict[str, str]]:
    """URL, body and headers for asking the upstream the same thing directly.

    Same envelope, same arguments, same protocol version. No `Authorization`,
    because there is nothing to authenticate to — see the module docstring.
    """
    if call.tool is None:
        msg = "tools/list has no meaningful direct equivalent across two upstreams"
        raise ValueError(msg)

    upstream, name = unqualified(call.tool)
    body = call.body()
    body["params"]["name"] = name

    return (
        DIRECT[upstream],
        body,
        {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": call.method,
            "Mcp-Name": name,
        },
    )


def uniquify(body: dict[str, Any], counter: int) -> dict[str, Any]:
    """A copy of `body` whose first argument is unique to `counter`.

    The counter goes in the *argument* rather than the tool name because the
    cache key covers arguments (ADR 0035) while policy covers the name — so
    this misses the cache without changing which rule applies. Changing the
    tool would do both, and would measure a different policy decision.

    Returns a new dict; the caller's body is reused across hundreds of requests
    and mutating it in place would make request N+1 depend on request N.
    """
    payload = dict(body)
    params = dict(payload.get("params") or {})
    arguments = dict(params.get("arguments") or {})
    if not arguments:
        return payload
    first = next(iter(arguments))
    arguments[first] = f"overhead-{counter}"
    params["arguments"] = arguments
    payload["params"] = params
    return payload


# ---------------------------------------------------------------------------
# Arithmetic
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Overhead:
    """What the gateway added, at each point of the distribution."""

    tool: str
    samples: int
    gateway: dict[int, float]
    direct: dict[int, float]

    @property
    def added(self) -> dict[int, float]:
        """Gateway minus direct, per percentile.

        Subtracting percentile from percentile is an approximation and worth
        naming as one: the p95 of a difference is not the difference of the
        p95s. It is the right approximation here because the two populations
        are measured separately against the same upstream — there is no pairing
        to preserve — and because the alternative, pairing request N of one run
        with request N of the other, would invent a correspondence that does
        not exist.
        """
        return {point: self.gateway[point] - self.direct[point] for point in self.gateway}

    @property
    def multiple(self) -> float:
        """How many times the direct call's median the gateway path costs.

        Below 1.0 on the cache-hit row, which is not a bug in the arithmetic:
        a hit never leaves the gateway.
        """
        median = self.direct.get(50, 0.0)
        return self.gateway[50] / median if median else float("inf")


def compare(tool: str, gateway: list[float], direct: list[float]) -> Overhead:
    """One row's two distributions, aligned for reporting."""
    return Overhead(
        tool=tool,
        samples=min(len(gateway), len(direct)),
        gateway=percentiles(gateway),
        direct=percentiles(direct),
    )


ENOUGH_TO_HAVE_A_SPREAD: Final = 2
"""Two runs. One measurement of a difference has no error bar."""


def resolution(controls: Sequence[float]) -> float:
    """How small a difference this harness can see, from its own control.

    The control is the **direct** call: the same request to the same mock,
    measured in every configuration, doing identical work every time. Whatever
    it varies by is variation the harness introduced — machine drift between
    container restarts, mostly — because the thing being measured did not
    change.

    So the spread of the control is **a lower bound on the noise in every other
    column**, and that asymmetry is the whole reason it is useful rather than
    decorative:

    - a marginal **at or below** this is certainly not resolved
    - a marginal **above** it is *not thereby* resolved — the gateway column
      carries this noise plus its own

    One-sided claims only. A harness that reported "3.1 ms, resolvable" from a
    floor computed this way would be overstating what the arithmetic supports.

    **One pass of the ladder already supplies this**, because the control is
    measured once per configuration and every configuration means another
    container restart — which is where most of the drift comes from. Repeating
    the ladder tightens the estimates and widens the sample this is drawn from;
    it is not what makes the floor available.

    ``inf`` for fewer than two controls, because one measurement of a difference
    has no error bar. Lesson 56, applied to this table rather than to the load
    test — where it was learned and then not carried across.
    """
    if len(controls) < ENOUGH_TO_HAVE_A_SPREAD:
        return float("inf")
    return max(controls) - min(controls)


def attributable(marginal: float, floor: float) -> bool:
    """Whether a step is bigger than the harness's own wobble.

    Absolute value, because **a negative marginal is the tell.** Removing work
    cannot make a system faster to no purpose; a rung that appears to *add* time
    when switched off is measuring drift, and if the report printed that as a
    small negative cost a reader would try to explain it.
    """
    return abs(marginal) > floor


class Step(StrEnum):
    """What a rung's marginal cost is worth believing.

    **Three outcomes, not two** — lesson 32, and it was a failing test that
    insisted on it. `attributable` was written as a magnitude check, and the
    first ablation produced a step of **-2.6 ms against a floor of 2.1**: bigger
    than the control's wobble, and *negative*.

    Removing work cannot make a system faster. So that value is not a resolved
    cost and it is not below the floor either — it is **proof that the floor
    understated the noise in that column**, which is exactly what `resolution`
    warns it might. A two-state answer had to call it one or the other and both
    were wrong.
    """

    RESOLVED = "resolved"
    BELOW_FLOOR = "below the harness's own variation"
    IMPOSSIBLE = "negative and above the floor: this column is noisier than the control"


def classify_step(step: float, floor: float) -> Step:
    """Which of the three a marginal is."""
    if not attributable(step, floor):
        return Step.BELOW_FLOOR
    if step < 0:
        return Step.IMPOSSIBLE
    return Step.RESOLVED


def spread(values: list[float]) -> str:
    """`mean [min-max]`, the shape every number in this project's perf work
    carries since task 61 found a single run understating by 30%."""
    if not values:
        return "—"
    return f"{statistics.mean(values):.1f} [{min(values):.1f}-{max(values):.1f}]"
