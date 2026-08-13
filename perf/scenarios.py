"""What a load test asks the gateway, and how to read what comes back.

Task 60, and deliberately **the half with no Locust import in it.** Locust
brings gevent, monkey-patching and a process model; none of that is testable in
a unit test, and all of the decisions worth arguing about live here instead:
which calls a realistic mix contains, what headers a real client sends, and —
the load-bearing one — **how to classify a response.**

The same split as `acp.audit.cli` vs `acp.cli`, for the same reason: put the
decisions in a module a test can reach, and the wiring in the one it cannot.
`perf/locustfile.py` is then thin enough to read in one sitting.

**Why classification is the interesting part.** The instinct is to count 2xx as
success and everything else as failure, and both halves of that are wrong here:

- A gateway that *refuses* a call is working. A load test that scores a policy
  denial or a rate-limit refusal as an error reports a failure rate that is
  really a description of the policy, and the number gets worse the better the
  gateway defends itself.
- A call held for a human (`input_required`) is neither served nor refused. It
  is the approval flow working, and it never touches an upstream — so folding
  its latency into the same bucket as a call that did makes both numbers mean
  nothing.

So every response is classified into an `Outcome`, latency is reported per
outcome, and the mix is printed beside the timings. **A p95 taken across
"served from cache", "reached an upstream" and "refused at the header" is a
number about the task mix, not about the gateway** — which is exactly the
number a default Locust run gives you, and exactly why this module exists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

PROTOCOL_VERSION: Final = "2026-07-28"
"""The revision this project targets (ADR 0001). Sent as a header *and* in the
envelope, because a real client sends both and the gateway checks they agree
(ADR 0008)."""

# Error codes, from `acp.exceptions`. Duplicated here rather than imported so
# the harness can be pointed at a *deployed* gateway without this repository's
# package installed — a load generator that can only test a build it was
# packaged with cannot be used against staging.
POLICY_DENIED: Final = -32040
RATE_LIMITED: Final = -32050
QUOTA_EXCEEDED: Final = -32051
AUDIT_UNAVAILABLE: Final = -32060
UNAUTHENTICATED: Final = -32030

UPSTREAM_ERRORS: Final = frozenset(range(-32018, -32009))
"""The `UpstreamError` family: timeout, unavailable, protocol, circuit open,
overloaded, rejected, unknown upstream, unknown tool.

Its own bucket because the first version counted these as defects, and a run at
20 users produced one — an upstream timeout under load, which is the *gateway
correctly reporting that a mock could not keep up*. Calling that a defect
points the reader at the wrong component, and "the only bucket that should be
zero" stops being true the moment you push hard enough to make an upstream
slow. **What it actually means is that this run measured the mock fleet as much
as the gateway**, which is a statement about the experiment, not about a bug.
"""


class Outcome(StrEnum):
    """What the gateway did, in the vocabulary the report is grouped by.

    Not `success`/`failure`. Six of these seven are the gateway working
    correctly, and only `FAILED` means something is wrong — which is the point:
    a load test's error rate should count *defects*, not *defences*.
    """

    SERVED = "served"
    """A result came back. Whether it was a cache hit is deliberately not
    guessed at from out here: the response is byte-identical either way (that is
    the cache's whole job), and inferring it from latency would be reading the
    thing being measured as though it were an input."""

    LISTED = "listed"
    """A catalogue, filtered by policy. Separate from `SERVED` because it never
    touches the result cache or the firewall, so its latency is a different
    population."""

    HELD = "held"
    """`input_required` — waiting for a person. Never reaches an upstream."""

    REFUSED = "refused"
    """Policy said no. **The gateway working**, and the fastest path through
    it — refusals from the pre-dispatch fast path never parse a body at all."""

    THROTTLED = "throttled"
    """Rate limit or quota. Also the gateway working, and separated from
    `REFUSED` because they mean different things to whoever reads the report:
    a refusal is about entitlement, a throttle is about load — and the second
    one appearing means *this run measured the limiter*, not the gateway."""

    UPSTREAM = "upstream"
    """An upstream failed and the gateway said so. Not a defect in the gateway
    — but at load it means the mocks are now part of what is being measured,
    which invalidates the run as a statement about gateway latency."""

    UNRECORDED = "unrecorded"
    """The audit log could not accept the record, so the call did not happen
    (fail-closed, ADR 0050). Its own bucket because it is the one outcome here
    that means the *deployment* is degraded rather than the caller being
    constrained — and under load it is the one to watch, since `fsync` per
    entry bounds throughput to the disk's sync rate."""

    FAILED = "failed"
    """A defect: a transport error, a 5xx, an unparseable body, or an MCP error
    code that is none of the above. **The only bucket that should be zero.**"""


@dataclass(frozen=True, slots=True)
class Call:
    """One request in the mix, and why it is in it."""

    name: str
    method: str
    tool: str | None
    arguments: dict[str, Any] | None
    weight: int
    why: str

    def body(self, request_id: int = 1) -> dict[str, Any]:
        """The JSON-RPC body, with the envelope the 2026-07-28 revision demands."""
        params: dict[str, Any] = {}
        if self.tool is not None:
            params["name"] = self.tool
            params["arguments"] = dict(self.arguments or {})
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "acp-load", "version": "0"},
        }
        return {"jsonrpc": "2.0", "id": request_id, "method": self.method, "params": params}

    def headers(self, token: str) -> dict[str, str]:
        """The headers a *real* client sends, `Mcp-Name` included.

        Not decoration. The pre-dispatch fast path (ADR 0043) reads
        `Mcp-Method` and `Mcp-Name` and **abstains when either is missing**, so
        a load generator that omits them silently benchmarks a path no real
        client takes — measuring the slow route while reporting numbers for the
        fast one. Task 55 found exactly this bug in the *test* suite; it would
        be worse here, because the output is a number somebody quotes.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": self.method,
            "Authorization": f"Bearer {token}",
        }
        if self.tool is not None:
            headers["Mcp-Name"] = self.tool
        return headers


# The mix. Weights are relative and the shape is meant to resemble one agent
# turn: mostly reads, a few of them repeated, an occasional expensive call, and
# one thing that stops for a human.
MIX: Final = (
    Call(
        name="tools/list",
        method="tools/list",
        tool=None,
        arguments=None,
        weight=2,
        why="every agent turn starts here, and it is the only call that exercises "
        "policy-based catalogue filtering",
    ),
    Call(
        name="search (repeated)",
        method="tools/call",
        tool="mock-a__search",
        arguments={"query": "retention policy"},
        weight=5,
        why="the same question twice in one turn is the case the result cache "
        "exists for, so this is the warm path after the first user hits it",
    ),
    Call(
        name="search (unique)",
        method="tools/call",
        tool="mock-a__search",
        arguments={"query": "__unique__"},
        weight=3,
        why="a cache miss that reaches an upstream and is screened by the "
        "firewall on the way back — the full path, and the slow one",
    ),
    Call(
        name="read_document",
        method="tools/call",
        tool="mock-a__read_document",
        arguments={"path": "runbooks/deploy.md"},
        weight=4,
        why="the most repeated call in a multi-step run, and cacheable for 60s",
    ),
    Call(
        name="summarize",
        method="tools/call",
        tool="mock-b__summarize",
        arguments={"text": "the quarterly retention review"},
        weight=1,
        why="costs 10 against the budget and is deliberately not cacheable, so "
        "it is what makes a quota bind before anything else does",
    ),
    Call(
        name="create_ticket (gated)",
        method="tools/call",
        tool="mock-a__create_ticket",
        arguments={"title": "load test"},
        weight=1,
        why="held for a human by the composed policy. Exercises the approval "
        "store's bound under load — it holds 256 and evicts oldest first, so a "
        "sustained run keeps it permanently full, which is the interesting state",
    ),
)

UNIQUE_MARKER: Final = "__unique__"
"""Replaced per request, so the call misses the cache every time. A literal
that a reader can grep for beats a boolean flag on `Call` that only one entry
sets."""


HTTP_UNAUTHORIZED: Final = 401
HTTP_FORBIDDEN: Final = 403
HTTP_SERVER_ERROR: Final = 500
NO_RESPONSE: Final = 0
"""A transport failure, which Locust reports as status 0."""


def classify(status: int, body: str) -> Outcome:
    """What the gateway did, from what a client can actually see.

    ``status`` is the HTTP status; ``body`` the raw response text. Both,
    because the two layers answer differently and both answers are real: a
    pre-dispatch refusal is an **HTTP 403 with no JSON-RPC body at all**
    (ADR 0043), while a refusal that got as far as the handler is a 200 with an
    error object inside. A classifier that only read one of them would report
    the same deployment differently depending on which layer refused — and the
    fast path is the one a real client hits most.
    """
    from_status = _from_status(status)
    if from_status is not None:
        return from_status

    frame = _frame(body)
    if frame is None:
        return Outcome.FAILED

    error = frame.get("error")
    if isinstance(error, dict):
        return _from_error_code(error.get("code"))
    return _from_result(frame.get("result"))


def _from_status(status: int) -> Outcome | None:
    """The outcomes decided before any body is read, or ``None`` to keep going."""
    if status == HTTP_FORBIDDEN:
        return Outcome.REFUSED
    if status == HTTP_UNAUTHORIZED:
        # The harness is misconfigured, not the gateway. Counted as a defect on
        # purpose: a load run against a gateway that refuses everything would
        # otherwise report a beautiful p99.
        return Outcome.FAILED
    if status >= HTTP_SERVER_ERROR or status == NO_RESPONSE:
        return Outcome.FAILED
    return None


def _from_result(result: object) -> Outcome:
    """Which shape of success came back."""
    if not isinstance(result, dict):
        return Outcome.FAILED
    if result.get("resultType") == "input_required":
        return Outcome.HELD
    if "tools" in result:
        return Outcome.LISTED
    if "content" in result:
        return Outcome.SERVED
    # A 200 whose result names nothing recognisable is a protocol change or a
    # bug. Either way it is not a served call, and quietly counting it as one
    # is how a real regression is absorbed into a healthy-looking report.
    return Outcome.FAILED


def _from_error_code(code: object) -> Outcome:
    if code == POLICY_DENIED:
        return Outcome.REFUSED
    if code in (RATE_LIMITED, QUOTA_EXCEEDED):
        return Outcome.THROTTLED
    if code == AUDIT_UNAVAILABLE:
        return Outcome.UNRECORDED
    if isinstance(code, int) and code in UPSTREAM_ERRORS:
        return Outcome.UPSTREAM
    return Outcome.FAILED


def _frame(body: str) -> dict[str, Any] | None:
    """One JSON-RPC frame, from JSON or from an SSE stream.

    The gateway may answer either way depending on what the client accepted, and
    a load generator that only parsed one would classify half a run as failures
    — an error rate produced entirely by the *measuring instrument*, which is
    the most expensive kind of wrong number because it looks like a finding.
    """
    text = body.strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            parsed: dict[str, Any] = json.loads(text)
        except json.JSONDecodeError:
            return None
        return parsed
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                frame: dict[str, Any] = json.loads(line[len("data:") :].strip())
            except json.JSONDecodeError:
                return None
            return frame
    return None


PRINCIPALS: Final = ("alice", "bob")
"""The demo users a run spreads itself across.

Two, not one, and chosen by an explicit index rather than by anything derived
from an object: the result cache, the rate limiter and the quota counter are
all keyed per principal (and per tenant, ADR 0051), so a single-identity run
exercises one bucket and one cache partition and reports a hit rate no real
deployment would see.
"""

WARMUP_SECONDS: Final = 3.0
"""Samples before this are discarded from the report.

The first requests of a run pay for a cold connection pool, a cold JWKS cache,
a cold result cache and whatever the runtime does on first execution of a code
path. Those are real costs and they are **not** the steady-state latency this
report claims to describe — at 30 seconds they land squarely in the p99, which
is the number people quote.

Discarded rather than reported separately because a warm-up figure from a
30-second run over one machine would be noise wearing a decimal point. The
count of discarded samples *is* printed, so the reader knows the window
existed.
"""


def principal_for(index: int, principals: tuple[str, ...] = PRINCIPALS) -> str:
    """Which demo user this simulated agent acts for.

    Round-robin on an explicit counter. The first version of this used
    ``id(self) % 2``, which **never alternates** — CPython object addresses are
    16-byte aligned, so the expression is 0 for every object ever allocated.
    Every simulated user became alice, the two-principal claim in ADR 0052 was
    false, and nothing failed: the run produced a full report from a single
    identity. Valid input, no error, silently different behaviour — the
    project's most repeated bug, this time in the measuring instrument.
    """
    return principals[index % len(principals)]


def after_warmup(
    samples: list[tuple[float, float]], *, warmup_seconds: float = WARMUP_SECONDS
) -> list[float]:
    """Latencies from samples taken after the warm-up window.

    ``samples`` is ``(seconds_since_run_start, latency_ms)``. Returns the
    latencies only, because that is all a percentile needs.

    **Returns everything when the filter would leave nothing.** A run shorter
    than the warm-up window should report the numbers it has, plainly, rather
    than an empty table that reads as "no requests" — the reader can see the
    request count and judge.
    """
    kept = [latency for at, latency in samples if at >= warmup_seconds]
    return kept if kept else [latency for _, latency in samples]


def percentiles(samples: list[float], points: tuple[int, ...] = (50, 95, 99)) -> dict[int, float]:
    """Nearest-rank percentiles over sorted samples, in the samples' own units.

    Nearest-rank rather than interpolated, deliberately: an interpolated p99 can
    report a latency **no request actually experienced**, which is a strange
    thing for a report whose purpose is to describe what requests experienced.
    Every number here is a real observation.

    Empty input returns an empty mapping rather than zeros — a bucket with no
    requests in it has no p95, and printing `0.0` would read as "very fast".
    """
    if not samples:
        return {}
    ordered = sorted(samples)
    result: dict[int, float] = {}
    for point in points:
        rank = max(1, -(-point * len(ordered) // 100))  # ceil, without float error
        result[point] = ordered[min(rank, len(ordered)) - 1]
    return result
