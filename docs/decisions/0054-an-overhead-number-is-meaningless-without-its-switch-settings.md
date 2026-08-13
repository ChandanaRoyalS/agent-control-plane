# ADR 0054 — An overhead number is meaningless without its switch settings

**Status:** accepted
**Date:** 2026-08-13

## Context

Task 62: *"Latency added versus a direct upstream call, with stated
methodology. The first question anyone who has run infrastructure will ask
you."*

The question is fair and the obvious way to answer it is wrong twice over.

**The first mistake is measuring under load.** Task 60's harness already
produces latency figures — 20 concurrent users, a realistic mix, per-outcome
percentiles. Reusing them would give a p50 of a few hundred milliseconds and it
would be a statement about a *queue*, not about the gateway. Under saturation
latency is dominated by waiting for a turn, which is a property of the offered
load and the machine. Overhead is the work the gateway does that the upstream
would not have done, and it is only visible when nothing is waiting.

So: **concurrency 1, sequential, alternating blocks**, which is the opposite of
task 60 and answers the other question.

**The second mistake is subtler and is the reason for this ADR.** Almost every
expensive thing this gateway does is optional, and most of the switches default
to off:

| | default |
|---|---|
| `firewall_mode` | `OFF` |
| `rate_limit_enabled` | `False` |
| `quota_enabled` | `False` |
| `cache_file` | `None` — nothing is cacheable |
| `cost_file` | `None` — every tool costs 1.0 |
| `provenance_framing_enabled` | `False` |

A gateway with those defaults authenticates, checks policy, exchanges a
credential and writes an audit record. That is a real gateway and it is *not the
gateway this project describes*. Publishing "the gateway adds N ms" measured
against it would be true of one configuration and quoted as a fact about the
system — the exact move that makes vendor benchmarks worthless.

This is not hypothetical here. `scripts/patch_compose_firewall.py` exists
because four merged features were inert in the only deployment anybody ran:
the config files were mounted, and *nothing pointed at them*. A benchmark run
before that patch would have measured a gateway with no cache, no cost table,
no framing and no screening, and nothing in its output would have said so.

## Decision

### 1. The measurement reads the gateway's configuration and prints it first

`perf/overhead.py` carries `FEATURES`: each optional piece of per-request work,
the environment variable that switches it on, and one line on what it adds. The
driver reads the **running container's** environment (`docker inspect
acp-gateway`) and prints the register above the numbers.

**The number and the switch settings that produced it come out of the same
run.** They can still be separated by somebody copying half the output, but they
cannot be separated by forgetting.

Read from the container and not from `docker-compose.yml`, because the two
disagree the moment anyone sets a variable on the command line — which this
project's own `make load-nofsync` does. The file describes a gateway that may
not be the one being measured; the container is the one being measured.

### 2. `ALWAYS_ON` is printed too

Policy evaluation, the pre-dispatch header check and the audit write have no
switch. A reader shown only a register of toggles, all off, would conclude the
gateway did nothing. It refused calls and recorded them, and those costs are in
every number.

### 3. A measurement whose premise is switched off is skipped, not run

`Measurement.requires` names the switches a row needs to mean what its label
says, and `applicable()` splits the rows accordingly. The cache-hit row requires
`ACP_CACHE_FILE`.

This is the decision the rest of the ADR exists to support. Run against a
gateway with no cache, that row produces **a completely plausible table in which
the cache saves nothing** — two near-identical distributions, a sensible-looking
1.0x, no error, no warning. The true finding, *that the cache was never switched
on*, would be absent from the output and from whatever document quoted it.

So the row is skipped and the reason is printed. The guard is mutation-checked:
with `requires` ignored, `test_the_cache_row_is_skipped_when_the_gateway_has_no_cache`
fails.

And if nothing can be measured honestly — no container, no readable environment
— the driver **refuses to print a number at all** rather than falling back to
assumptions.

### 4. Two rows, one tool, both cache outcomes

`search (unique)` forced to miss, and `search (repeated)` left to hit.

Same tool on both rows deliberately: changing the tool would change the
*upstream's* work as well as the gateway's, and the difference would stop being
attributable to the thing being measured.

The cache-hit row was included because "the gateway makes calls slower" is not
a complete sentence about a system that also answers some calls from memory
without crossing the network. A benchmark reporting only the miss row would be
accurate and would mislead — which describes most benchmarks.

> **This decision predicted the hit row would show a *negative* overhead. It
> does not.** See "the prediction this ADR made, and lost" below. The row stays;
> its claim is now the smaller and true one — the difference between the rows is
> what the cache is worth.

### 5. The counter goes in the argument, not the tool name

Forcing a cache miss means varying something the cache key covers. The key
covers arguments (ADR 0035); policy covers the name. Varying the name would miss
the cache *and* change which policy rule applies, measuring a different decision
while labelling it the same one.

### 6. Three alternating rounds, 10 warm-up calls discarded

Task 61 established that a laptop warms measurably over a five-minute run, so
`direct` then `gateway` would charge the whole drift to whichever ran second.
Alternating spreads it. The discarded warm-up covers a cold connection pool, a
cold JWKS cache, an unexchanged credential and a cold result cache — all real
costs, and none of them the steady-state figure this reports.

## Measured — and the register earned its place on the first run

One machine, `make up` immediately before, 150 samples each side per row.

### What the register found before any number was printed

```
[on ] authentication      [on ] result cache          [on ] injection screening
[on ] credential exchange [on ] cost-weighted budget  [on ] provenance framing
[OFF] rate limit          [OFF] quota                 [on ] audit fsync
```

**`ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED` are not set in
`docker-compose.yml`, and both default to `False`.** `ACP_COST_FILE` *is* set,
so `config/costs.yaml` is parsed at every start — and
`gateway/server.py:_charge` opens with

```python
if payer is None or (limiter is None and quota is None):
    return
```

**A cost table is loaded and never consulted.** This is the wiring bug that
`scripts/patch_compose_firewall.py` was written for, in its sixth instance and
its most complete form: not a feature that does nothing, but a *file that is
read* to feed a decision nothing makes. It is fixed separately from this task,
because turning two switches on changes what the numbers below describe, and a
measurement that moves under its own conclusions is not a measurement.

The number below is therefore honest about a gateway with no budget enforcement.
The register says so, which is the entire argument of this ADR arriving on its
first run.

### The numbers

| row | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|
| cache miss | 5.3 ms | 38.1 ms | **+32.8 ms** | +52.6 ms | +113.7 ms |
| cache hit | 6.8 ms | 22.8 ms | **+16.0 ms** | +41.7 ms | +97.4 ms |

**The cache is worth 15.3 ms**, which is the difference between the two gateway
figures and is the only claim either row supports on its own.

### The prediction this ADR made, and lost

Decision 4 said the cache-hit row was *"where the overhead goes negative"* — that
a call answered from memory would beat one crossing the network.

**It does not, and it is not close.** 22.8 ms against 6.8 ms.

The arithmetic that should have been done before writing the claim: a cache hit
removes **the upstream round trip and nothing else**. Against a mock, that round
trip is about 6 ms. The gateway still authenticates, still evaluates policy,
still screens and frames the result, and still waits for an audit record to
reach the disk. **Its own fixed cost is larger than the entire thing the cache
eliminates**, so a hit is faster than a miss and slower than going direct.

Recorded here rather than quietly edited out, on the practice ADR 0053
established. The row is kept, with a smaller and true claim attached: *the
difference between the rows is what the cache is worth.*

The prediction is not wrong in general — against an upstream that takes 200 ms,
a 16 ms hit wins by an order of magnitude. It is wrong **here**, and "here" is
what was measured and therefore all that may be said.

### Attributed — `make overhead-ab`, and both predictions scored

Four runs, 2x2 across `ACP_AUDIT_FSYNC` and `ACP_HEALTH_PROBING_ENABLED`.
**Cache-hit gateway p50** is the pure fixed cost, since it touches no network:

| | probing on | probing off |
|---|---|---|
| **fsync on** | 19.1 ms | 20.0 ms |
| **fsync off** | 13.5 ms | 11.2 ms |

And the cache-miss row's **added p95**, which is where a tail would show:

| | probing on | probing off |
|---|---|---|
| **fsync on** | +106.5 ms | +57.5 ms |
| **fsync off** | +30.2 ms | +20.0 ms |

**Prediction 1 — "`fsync=off` drops the fixed cost into single digits" — wrong.**
It drops it by 5.6–8.8 ms, roughly a third. The audit `fsync` is the single
largest item and it is **not most of the cost**. Task 61 made it the obvious
suspect, and obvious carried about a third of the answer.

**Prediction 2 — "probing barely moves the p50 and visibly improves the tail" —
right, and by more than expected.** On the median it moves +0.9 and −2.3 ms,
which straddles zero and sits inside the run-to-run noise: the *direct* p50
across these four runs was 6.4, 5.0, 7.1 and 5.0 ms, and that path is a constant.
**A difference smaller than the variation of a constant is not a difference.**

On the tail it is unambiguous, in the same direction under both `fsync` settings
and large: **+106.5 → +57.5 ms**. A catalogue refetch from every upstream every
five seconds, on the same event loop, cannot touch the median of 150 samples and
can own a p95. That is the shape a periodic background job has, and it is why
`BACKGROUND` is a separate register from `FEATURES`.

### And one number that fell out for free

In the leanest configuration, cache miss 20.9 ms and cache hit 11.2 ms at the
gateway. **The upstream leg costs the gateway 9.7 ms**, against 5.2 ms for the
host's own direct call to the same mock — even though the gateway's leg stays
inside the Docker network and the host's crosses a published-port proxy.

So about **4.5 ms of the gateway's upstream call is the gateway's own client
work** — envelope construction, the retry and breaker wrappers, response parsing
and screening the fresh body — rather than the network. The extra hop that this
ADR declared as counted-but-not-the-gateway's-job is therefore *smaller* than it
looks, and most of the miss/hit gap is work rather than distance.

Derived rather than measured, from two rows of one run. Stated as an estimate.

### 11 ms unattributed, and the ladder that itemises it

With `fsync` and probing both off, a request that touches no network still costs
**11.2 ms**. Unexplained is the weakest thing a performance number can be, so
the remaining candidates get the same treatment: `make overhead-ablate` walks
`perf.overhead.ABLATION`, removing one switch at a time and printing the
marginal cost of each.

Cumulative rather than leave-one-out, so the rungs sum and the last row is a
floor. The cost of that choice — an interaction between two switches is billed
to whichever is removed first — is stated in the ladder rather than hidden.

**One rung was missing from the register entirely.** `OTEL_TRACES_EXPORTER` ships
a span per request over OTLP to Jaeger, which is per-request work by any reading.
It was absent because `FEATURES` was assembled by reading `GatewaySettings`, and
tracing is configured by OpenTelemetry's standard variables instead. **A register
built from one source of truth misses everything configured by another** — which
is the same failure as the compose wiring bug above, arriving from the other
direction.

### The number this leaves open, and how it gets closed

*Written before the run above, and kept because scoring it is the point.*

16.0 ms of fixed cost, for a request that touches no network. Task 61 makes the
audit `fsync` the obvious suspect, and **obvious is not measured** — which is
ADR 0053's own methodological finding, one task old.

So `make overhead-ab` runs the same measurement across the two switches that
could plausibly own it: `ACP_AUDIT_FSYNC` (the caller waiting on the disk, per
audited call) and `ACP_HEALTH_PROBING_ENABLED` (the catalogue prober, which is
not on the request path but shares the loop with it every five seconds, and is
therefore a candidate for the **p99 rather than the p50**).

Four runs, each printing its own switch line, so the attribution and the
configuration it was measured under cannot be separated.

**The prober is why `BACKGROUND` is a second register rather than a tenth
`FEATURES` entry.** `FEATURES` says *this request did this work*; `BACKGROUND`
says *something else was running while it did*. Folding them together would
invite a reader to charge the prober to a call's cost, which is a different
claim and a false one.

## Itemised — and the ablation's main finding is about the ablation

One pass, six configurations. **Cache hit p50** is the fixed cost, since it
touches no network:

| configuration | gateway | step | control (direct) |
|---|---|---|---|
| everything on | 17.8 ms | — | |
| − audit fsync | 12.0 ms | **+5.8** | |
| − health probing | 10.4 ms | · | |
| − injection screening | 12.1 ms | · | |
| − provenance framing | 11.7 ms | · | |
| − trace export | 10.8 ms | · | 5.2 ms |

**One of five rungs resolved.** The other four moved the number by 1.6, −1.7,
0.4 and 1.0 ms — and the control, which is the same request to the same mock
doing identical work in every configuration, wandered by **2.1 ms** across the
six runs. Two of the four steps were *negative*: removing work appeared to make
the system slower.

Printing those as small costs would have been fabrication. So the report doesn't:
a step at or below the control's own spread prints as `·` and is **not
attributed**.

### The four predictions

| written before the run | verdict |
|---|---|
| screening is the largest remaining item, 2–4 ms | **wrong** — its step is −1.7 ms, below the floor and the wrong sign |
| trace export is near-invisible at the median | right — 1.0 ms, below the floor |
| framing is under 1 ms | right — 0.4 ms, below the floor |
| the floor lands at 5–7 ms | right — 10.8 gateway against 5.2 direct, **5.6 ms added** |

Two of four, and the two right ones are right in the weak sense that *"too small
to see"* was the prediction and *"too small to see"* is what came back.

### So the 17.8 ms breaks down as

| | |
|---|---|
| the direct call itself — network and the mock | 5.2 ms |
| **the audit `fsync`** | **5.8 ms** |
| everything else, individually unresolved | ~6.8 ms |

Authentication, policy evaluation, the audit write minus its `fsync`, the
pre-dispatch check, the framework and the extra hop are in that last row and
**this instrument cannot separate them.** Each is smaller than the variation
between two container restarts, and each rung *requires* a restart because these
are start-up settings. More samples inside a run does not help; only repeating
the whole ladder does, which is what `--repeat` is for.

### The floor caught an error in the floor

The first version computed one resolution from the control's **p50** and applied
it to the **p95** column as well. That column then reported two steps that were
negative *and* above the floor — impossible as costs, since removing work cannot
make a system faster.

Which is the report saying the floor was wrong for that column, and it was. **A
tail is structurally noisier than a median**: a p95 is one of the slowest few
samples and moves with whatever the machine was doing, while a p50 sits where the
distribution is densest. Each table now computes its floor from the control at
its own percentile.

That also forced a third outcome — `Step.RESOLVED`, `BELOW_FLOOR`, `IMPOSSIBLE` —
because a two-state answer had to call an impossible value one or the other and
both were wrong. Lesson 32, arriving for the third time in this project.

### Where this stops, and what would go further

**Not with a bigger sample.** The residual is six or seven milliseconds spread
across five or six mechanisms, against an instrument whose own restart-to-restart
variation is two. That is a resolution limit of the *method*, not of the run
length.

What would go further is per-stage timing from inside the process: `py-spy`
against the container, or the spans the gateway already emits, read out of Jaeger
rather than looked at. ADR 0053 declared `py-spy` an honest cut on the grounds
that an A/B was stronger evidence and had already named the function. **That
reasoning held there and stops holding here** — the A/B has named everything it
can name, and what is left is exactly the question a profiler answers.

Declared as the next step rather than done, and it is a task, not a paragraph.

## What is counted as overhead that arguably is not

Declared rather than netted out, because both adjustments would flatter the
number and neither can be measured with what is built.

**One extra network hop.** The direct call is one hop; the gateway path is two,
because the gateway sits between. Loopback inside one Docker network is small
and not zero. Separating it needs a null gateway that forwards without deciding
— a fair thing to want, and not built.

**The direct path is unauthenticated.** The mock has no auth to offer, so the
comparison charges the gateway for the whole cost of authentication. That is
correct: authentication is part of what the gateway adds. It is stated because a
reader comparing this figure with a proxy that *does* authenticate on both sides
is comparing different quantities.

## Consequences

- `perf/overhead.py` — `FEATURES`, `ALWAYS_ON`, `Measurement`, `applicable`,
  `parse_env`, `uniquify`, `Overhead`, and the shared request builders.
- `scripts/measure_overhead.py` — the driver; refuses without a readable
  container environment.
- `make overhead`, via an asserted patch anchored on `load-ab`.
- 72 unit tests across `tests/unit/perf/`, up from 37.
- The mock upstreams' ports were already published by compose, so no change to
  `docker-compose.yml` was needed for the direct half.

## The honest cuts

**No per-stage breakdown.** "3 ms added" does not say whether it went to policy,
to screening or to the audit write. The gateway emits OpenTelemetry spans and
Jaeger is in the compose stack, so the data exists; turning it into a table is
a distinct piece of work and is not this task. `FEATURES` is the coarse version
— it says which stages ran, not what each cost.

**No null-gateway baseline**, so the extra hop stays inside the number — above.

**One machine, mock upstreams that answer in microseconds.** This is the least
favourable setting for a gateway: the overhead is compared against an upstream
doing almost nothing. Against a real upstream — a network call, a database, a
model — the same absolute cost sits under a much larger number, and the
*multiple* collapses while the *added milliseconds* stay roughly the same. The
added figure is the one to quote; the multiple is the one that would flatter or
damn depending on what it was measured against.

## References

- ADR 0035 — the result cache and what its key covers
- ADR 0043 — the pre-dispatch check on the routing headers
- ADR 0050 §8 — `fsync` per audit entry
- ADR 0052 — task 60's harness, which measures the other question
- ADR 0053 — the defect that harness found, and the repetition discipline
- `perf/README.md` — the measured figures
