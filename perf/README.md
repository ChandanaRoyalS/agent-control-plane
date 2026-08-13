# Load and latency measurement

Phase 8. `perf/scenarios.py` decides what to ask and how to read the answer;
`perf/locustfile.py` is the Locust wiring. `perf/overhead.py` and
`scripts/measure_overhead.py` are task 62's separate measurement — **what the
gateway costs against a direct upstream call**, which is a different question
and is measured the opposite way.

Two questions, and it is worth being clear which is which before reading any
number below:

| | question | concurrency |
|---|---|---|
| `make load` | what happens when it is busy | 20 users |
| `make overhead` | what the gateway itself costs | one request in flight |

A p50 from the first is mostly a statement about a queue. Only the second is
the gateway's own cost. See ADR 0054.

## Running it

```bash
make up            # the stack must be up: gateway, mocks, Keycloak
make load          # 30 seconds, 20 users
make load-long     # 5 minutes, 100 users
make load-ab       # six alternating fsync on/off runs, so the numbers have a range
make overhead      # sequential, against a direct upstream call (task 62)
make overhead-ab   # the same, across fsync and prober on/off, to attribute it
make overhead-ablate  # remove one thing at a time, and itemise the total
make overhead-ablate-repeat   # the same ladder x3, for a tighter floor
```

Or drive it yourself, including the web UI:

```bash
uv run locust -f perf/locustfile.py --host http://127.0.0.1:8080
```

## How to read the output

The report is grouped **by what the gateway did**, not by request name and not
in aggregate:

```
  outcome        count   share       p50       p95       p99
  served          1204   61.2%     4.1ms     9.8ms    16.2ms
  listed           241   12.3%     2.0ms     5.1ms     7.7ms
  held             122    6.2%     1.8ms     3.9ms     5.2ms
  refused            0    0.0%         —         —         —
```

That grouping is the point. **A p95 taken across served, refused and held
calls is a statement about the task mix rather than about the gateway** — a
refusal at the routing header never parses a body, a held call never reaches an
upstream, and a cache hit never leaves the process. Averaging them produces one
number that describes none of them, and it moves whenever somebody changes the
policy.

Three lines in the report are warnings rather than data:

- **`FAILED` is non-zero** — defects, not defences. Read the gateway's logs
  before believing anything else in the table.
- **`THROTTLED` is non-zero** — this run measured the rate limiter. The
  latencies describe a queue as much as a gateway.
- **`UNRECORDED` is non-zero** — the audit sink could not keep up, so those
  calls did not happen (fail-closed, ADR 0050). `fsync` per entry is the first
  suspect, and this is the number Phase 8 exists to put a figure on.

## What these numbers are not

**They are not a benchmark.** They describe one machine, one mock fleet and one
task mix, with everything running on the same host through Docker's network
stack. They are useful for three things and no others:

1. **Finding where time goes** — the input to task 61's profiling.
2. **Detecting a regression** on the same machine, between two runs.
3. **Sizing the gateway's overhead** against a direct call (task 62), which is
   the only comparison here that means anything to somebody else.

Anyone quoting a p99 from this harness as "the Agent Control Plane's latency"
is quoting the mocks, the loopback interface and the laptop.

## Why the mocks make this worth doing at all

The mock fleet answers in microseconds and deterministically, so **almost all
of the measured latency is the gateway's own work**: authentication, policy
evaluation, budget accounting, cache lookup, firewall screening, provenance
framing and the audit write. Against a real upstream that work would be
invisible under the network.

That is also the trap. The mocks can inject latency and errors on purpose
(`CHAOS_MODE`), which is what makes the resilience tests possible and what
would silently ruin a measurement. **The harness refuses to start when
`CHAOS_MODE` is set in the environment it can see.** It cannot see a value
baked into an already-running container, so if a number looks wrong:

```bash
make down && make up
```

## What the first run found

The harness's own first run found two bugs **in the harness**, which is the
argument for treating a load generator as code rather than as a command:

1. **It minted a token per simulated user.** Twenty simultaneous logins for one
   account against a realm with `bruteForceProtected: true` is structurally a
   password-guessing attack, and Keycloak locked the account — answering
   `invalid_grant: Invalid user credentials`, which is deliberately
   indistinguishable from a wrong password. Half the fleet died at startup.
   ADR 0052 had already rejected per-*request* minting for making this a
   Keycloak benchmark; per-*user* minting was the same mistake moved to
   startup, where it was harder to see. Now: one token per principal, per
   process, behind a lock — two logins instead of twenty.

2. **The two-principal claim was false.** The user was chosen with
   `id(self) % 2`, and CPython object addresses are 16-byte aligned, so that
   expression is 0 for every object ever allocated. Every simulated user was
   alice. The run exercised one cache partition and one rate-limit bucket while
   the report implied two. Now an explicit round-robin counter, with a
   regression test that also asserts the old expression *would* have failed.

**And the report printed a confident table through both.** So it now prints how
many users actually started, of how many were requested, and warns when the
fleet is smaller than asked for. A number's provenance is part of the number.

## The measurement: what `fsync` costs, and why it costs more than it should

Same machine, same mix, same 20 users, 30 seconds. The only difference is
`ACP_AUDIT_FSYNC`:

| | fsync on | fsync off | speed-up |
|---|---|---|---|
| **throughput** | 44.7 req/s | **114.5 req/s** | **2.56x** |
| served p50 | 222.4 ms | 94.2 ms | 2.36x |
| served p95 | 903.9 ms | 386.7 ms | 2.34x |
| served p99 | 1314.2 ms | 543.3 ms | 2.42x |
| listed p50 | 191.1 ms | 81.9 ms | 2.33x |
| **listed p95** | **2819.4 ms** | **223.9 ms** | **12.59x** |
| held p95 | 725.0 ms | 226.8 ms | 3.20x |

ADR 0050 §8 declared this cost three tasks ago and said Phase 8 would measure
it. **It is 2.56x of throughput.**

### And the `listed` row says something the throughput number does not

`tools/list` **writes no audit record.** Look at `on_list_tools`: it filters a
catalogue and returns. It does not touch the sink at any point.

It was **12.6x slower at p95** with `fsync` on.

It was not waiting for its own disk write, because it does not make one. It was
waiting for *somebody else's* — because `FileAuditSink.append` is a synchronous
method calling `os.fsync`, invoked from an `async def` handler, **on the event
loop thread**. While one request's audit record reaches the platter, every
other in-flight request on that loop is stopped, whether or not it writes
anything.

That is head-of-line blocking, and it is a different defect from "durability is
expensive":

- **Durability is expensive** is a trade a deployment can make knowingly. The
  2.56x is the honest price of a record that survives power loss.
- **A blocking syscall on the event loop** is a bug. It charges that price to
  requests that are not buying anything, and it converts a per-request cost
  into a whole-process one.

The fix is not to turn `fsync` off — that trades away the guarantee ADR 0050
exists to provide, in a system whose entire argument is that an unrecorded call
must not happen. The fix is to get the write off the loop while keeping it
awaited, so the calling request still cannot proceed until its record is
durable and every other request keeps running.

**That is task 61**, and this is the measurement that tells it exactly where to
look — before a profiler was even attached.

## The measurement: three repetitions, alternating

A single 30-second run on a laptop is a sample, not a measurement. Six runs,
alternating on/off so machine drift hits both configurations equally
(`make load-ab`):

| | fsync on | fsync off |
|---|---|---|
| throughput | **56.7 req/s** [49.7–66.2] | **120.1 req/s** [115.4–126.2] |
| served p50 | 299.7 ms [261–321] | 97.0 ms [90–105] |
| served p95 | 611.7 ms [536–691] | 405.5 ms [395–416] |
| **listed p50** | **15.1 ms** [14.6–15.6] | 83.5 ms [73–93] |
| **listed p95** | **35.7 ms** [30.4–40.4] | 160.5 ms [149–166] |

**Durability costs 2.14x of throughput** (per-rep: 2.32, 2.18, 1.91). That is
the number ADR 0050 §8 promised Phase 8 would produce.

### The fix, against the state before it

| | before | after (n=3) | |
|---|---|---|---|
| listed p50 | 191.1 ms | **15.1 ms** (sd 0.4) | **13x** |
| listed p95 | 2819.4 ms | **35.7 ms** (sd 4.1) | **79x** |

Both deltas are two orders of magnitude larger than the run-to-run spread, so
they are real whatever the noise. The "before" column is a single run and the
throughput comparison is therefore *not* claimed as a number.

### The row that proves it twice

`listed` p50 is **15.1 ms with `fsync` on and 83.5 ms with it off** — the
catalogue listing is 5.5x *faster* in the slower configuration.

That is not a mistake. `tools/list` is pure CPU: filter a catalogue, return. Its
latency now tracks **how contended the event loop is**, which is exactly what it
should track. With `fsync` on the gateway runs at 57 req/s because audited work
waits on the disk, so fewer requests compete for CPU and the listing sails
through; with `fsync` off it runs at 120 req/s and the loop is genuinely busy.

Before the fix it was 191 ms — tracking the disk it never touches.

### What the repetitions found about the method

Throughput **rose monotonically across reps in both configurations** — 49.7,
54.3, 66.2 and 115.4, 118.6, 126.2. The machine warms over five minutes, so any
single run understates, and the first run of a session understates most.

That explains the one earlier number that looked like a regression: a run
measuring 41.9 req/s, taken immediately after a 40-second image build, sits
*below* the 49.7–66.2 range this code produces when measured three times. It
was an outlier, not a change — and it would have gone into an ADR as a fact if
nobody had repeated it.

> **A number without a repetition count is a sample wearing a decimal point.**

## Gateway overhead — what it costs against a direct call

    make up
    make overhead

A different question from everything above, and deliberately measured the
opposite way: **sequential, one request in flight**. Under load a p50 is
dominated by queueing, which is a property of the offered load rather than of
the gateway. Overhead is the work the gateway does that the upstream would not
have done, and it is only visible when nothing is waiting. See ADR 0054.

### It prints the gateway's switch settings before it prints a number

Most of what the gateway does per request is optional, and most of the switches
default to off — `firewall_mode` is `OFF`, `rate_limit_enabled` and
`quota_enabled` are `False`, `cache_file` and `cost_file` are `None`. So "the
gateway adds N ms" is not a fact about the gateway; it is a fact about **one
gateway configured one way**.

The driver reads the running container's environment and prints a register:

```
    [on ] authentication         signature check against the cached JWKS, ...
    [on ] result cache           a keyed lookup before dispatch, and a store after it
    [OFF] quota                  a windowed counter per principal
    ...
    Not switchable, and in every number below:
    [on ] the pre-dispatch header check (ADR 0043)
    [on ] policy evaluation down to the argument
    [on ] the hash-chained audit write
```

Read from `docker inspect acp-gateway` rather than from `docker-compose.yml`,
because the two disagree the moment anybody sets a variable on the command line
— `make load-nofsync` does exactly that. And if the container cannot be read,
**no number is printed at all**.

### A row whose premise is off is skipped, not quietly run as something else

The cache-hit row declares `ACP_CACHE_FILE` as a requirement. Run against a
gateway with no cache configured it would produce a perfectly plausible table
in which the cache saves nothing — no error, no warning, and the real finding
(*the cache was never switched on*) nowhere in the output. So it is skipped, with
the reason printed.

### Two rows, one tool

| row | what it measures |
|---|---|
| cache miss | the full path — policy, budget, a lookup that misses, credential exchange, a real upstream call, screening, the audit write |
| cache hit | the same question asked twice, answered from memory without crossing the network |

Both are `mock-a__search`. Changing the tool between rows would change the
*upstream's* work as well as the gateway's, and the difference would stop being
attributable.

The cache-hit row is here because "the gateway makes calls slower" is not a
complete sentence about a system that also answers some calls without leaving
the process. **It was predicted to go negative and does not** — see the measured
section below, which is the more interesting outcome.

### Measured

One machine, `make up` immediately before, 150 samples each side per row.

**The register found something before a number was printed.**
`ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED` are not set in
`docker-compose.yml` and both default to `False` — while `ACP_COST_FILE` *is*
set. So `config/costs.yaml` is parsed at every start and never consulted, because
`_charge` returns immediately when there is no limiter and no quota. **A cost
table loaded to feed a decision nothing makes.** Fixed separately, because
turning two switches on changes what these numbers describe.

| row | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|
| cache miss | 5.3 ms | 38.1 ms | **+32.8 ms** | +52.6 ms | +113.7 ms |
| cache hit | 6.8 ms | 22.8 ms | **+16.0 ms** | +41.7 ms | +97.4 ms |

**The cache is worth 15.3 ms** — the difference between the two gateway figures,
and the only claim either row supports on its own.

#### The prediction that lost

This file and ADR 0054 both said the cache-hit row was where the overhead goes
negative. **22.8 ms against 6.8 ms.** Not close.

A cache hit removes the upstream round trip and nothing else, and against a mock
that round trip is about 6 ms. The gateway still authenticates, evaluates policy,
screens, frames, and waits for an audit record to reach the disk. **Its own fixed
cost is larger than the entire thing the cache eliminates.**

Wrong here, not wrong in general: against an upstream taking 200 ms, a 16 ms hit
wins by an order of magnitude. "Here" is what was measured and therefore all
that may be said.

#### Attributed, and both predictions scored

**Cache-hit gateway p50** — the pure fixed cost, since it touches no network:

| | probing on | probing off |
|---|---|---|
| **fsync on** | 19.1 ms | 20.0 ms |
| **fsync off** | 13.5 ms | 11.2 ms |

**Cache-miss added p95** — where a tail would show:

| | probing on | probing off |
|---|---|---|
| **fsync on** | +106.5 ms | +57.5 ms |
| **fsync off** | +30.2 ms | +20.0 ms |

**The `fsync` prediction was wrong.** It costs 5.6–8.8 ms, about a third of the
fixed cost — the largest single item, and not most of it.

**The prober prediction was right and larger than expected.** On the median it
moves +0.9 and −2.3 ms, which straddles zero and sits inside the run-to-run
noise: the *direct* p50 across these four runs was 6.4, 5.0, 7.1 and 5.0 ms, and
that path is a constant. **A difference smaller than the variation of a constant
is not a difference.** On the tail it is unambiguous and consistent under both
`fsync` settings: **+106.5 → +57.5 ms**.

A periodic background job cannot touch the median of 150 samples and can own a
p95. That is why `BACKGROUND` is a separate register.

#### One number that fell out for free

Leanest configuration: cache miss 20.9 ms, cache hit 11.2 ms at the gateway. So
**the upstream leg costs the gateway 9.7 ms**, against 5.2 ms for the host's own
direct call to the same mock — and the gateway's leg stays inside the Docker
network while the host's crosses a published-port proxy.

About **4.5 ms of that is the gateway's own client work** — envelope
construction, retry and breaker wrappers, response parsing, screening the fresh
body — rather than distance. The "extra hop" is smaller than it looks.

Derived from two rows of one run. An estimate, stated as one.

#### 11 ms unattributed, and the ladder that itemises it

A request that touches no network still costs 16 ms. Task 61 makes the audit
`fsync` the obvious suspect, and **obvious is not measured** — which is ADR
0053's own finding, one task old.

With `fsync` and probing both off, a request touching no network still costs
11.2 ms. `make overhead-ablate` walks `perf.overhead.ABLATION`, removing one
switch at a time and printing the marginal cost of each:

```
- audit fsync            the caller waiting for the record to reach the disk
- health probing         a catalogue refetch from every upstream every 5 seconds
- injection screening    every detector run over the result body
- provenance framing     two content blocks fencing the result as retrieved data
- trace export           a span per request, shipped over OTLP
```

Cumulative, so the rungs sum and the last row is a **floor** — what remains is
authentication, policy, the audit write without its `fsync`, the pre-dispatch
check, the framework and the extra hop. The cost of that choice: an interaction
between two switches is billed to whichever is removed first.

**One rung was missing from the register entirely.** `OTEL_TRACES_EXPORTER` ships
a span per request over OTLP, which is per-request work by any reading. It was
absent because `FEATURES` was assembled by reading `GatewaySettings`, and tracing
is configured by OpenTelemetry's own variables. **A register built from one
source of truth misses everything configured by another.**

#### Itemised — and what the ablation could not see

One pass, six configurations. **Cache hit p50**, the fixed cost:

| configuration | gateway | step |
|---|---|---|
| everything on | 17.8 ms | — |
| − audit fsync | 12.0 ms | **+5.8** |
| − health probing | 10.4 ms | · |
| − injection screening | 12.1 ms | · |
| − provenance framing | 11.7 ms | · |
| − trace export | 10.8 ms | · |
| *a direct call* | *5.2 ms* | |

**One of five rungs resolved.** The other four moved the number by 1.6, −1.7,
0.4 and 1.0 ms while **the control wandered by 2.1 ms** — and two of those steps
were negative, which as a cost is impossible.

So the report doesn't print them. A step at or below the control's own spread
prints as `·` and is not attributed. `?` marks the third case: negative *and*
above the floor, which means the floor understated that column's noise.

**The control is on every row for this reason.** The first version printed the
direct call once, at the bottom, which hid the only honest scale for reading the
step column against.

##### The 17.8 ms

| | |
|---|---|
| the direct call itself — network and the mock | 5.2 ms |
| **the audit `fsync`** | **5.8 ms** |
| everything else, individually unresolved | ~6.8 ms |

Authentication, policy, the audit write minus its `fsync`, the pre-dispatch
check, the framework and the extra hop are all in that last row, and **this
instrument cannot separate them**: each is smaller than the variation between
two container restarts, and every rung needs a restart because these are
start-up settings.

##### The floor caught an error in the floor

One resolution was first computed from the control's p50 and applied to the p95
column too. That column then reported steps that were negative *and* above the
floor. **A tail is structurally noisier than a median**, so a floor measured at
one percentile says nothing about the other. Each table now computes its own.

##### Where this stops

Not with a bigger sample — the residual is ~7 ms across five mechanisms against
an instrument whose own restart-to-restart variation is 2 ms. That is a
resolution limit of the method.

What goes further is per-stage timing from inside the process: `py-spy`, or the
spans the gateway already emits read out of Jaeger. ADR 0053 declared `py-spy` an
honest cut because an A/B was stronger evidence and had already named the
function. **That reasoning held there and stops holding here.**

### What is counted as overhead that arguably is not

- **One extra network hop.** The gateway sits in the middle, so its path is two
  hops and the direct path is one. Loopback inside a Docker network is small and
  not zero. Separating it needs a null gateway that forwards without deciding,
  which is not built.
- **The direct path is unauthenticated**, because the mock has no auth to offer.
  The gateway is charged for all of authentication. That is correct — it is part
  of what the gateway adds — and it is stated because comparing this figure with
  a proxy that authenticates on both sides compares different quantities.

### And the caveat that matters most

**One machine, mock upstreams that answer in microseconds.** This is the least
favourable setting a gateway can be measured in: its cost is compared against an
upstream doing almost nothing. Against a real upstream — a network call, a
database, a model — the same absolute cost sits under a much larger number.

**Quote the added milliseconds, not the multiple.** The multiple is a statement
about how fast the mock is.

## Reproducibility checklist

A throughput number without these is not reproducible, so the report prints the
first two and this file records the rest:

- **wait time** — 0–50 ms per user. **This is not a saturation test.** At 20
  users with a ~30 ms round trip, that ceiling is roughly 400 req/s of offered
  load and the observed throughput is far below it — so these numbers describe
  *latency under light load*, not capacity. Task 62 needs the latency; a
  capacity figure needs `--users` in the hundreds and a wait time of zero, and
  should be measured deliberately rather than inferred from this
- **users started, not users requested** — printed in the report
- **user count and duration** — printed by Locust
- **the mix** — `perf/scenarios.MIX`, each entry carrying the reason it is there
- **the warm-up window** — the first 3 seconds are discarded from the
  percentiles, and the discarded count is printed. Cold pools, a cold JWKS
  cache and a cold result cache are real costs but are not steady state, and in
  a 30-second run they land squarely in the p99
- **the deployment** — `config/policy.compose.yaml`, `config/cache.yaml`,
  `config/costs.yaml`, and whether `ACP_AUDIT_FSYNC` is on. `make overhead`
  reads this out of the running container and prints it; `make load` does not
  yet, and that is the obvious thing to copy across
- **two principals** — the run alternates alice and bob, because the cache, the
  rate limiter and the quota counter are all keyed per principal and a
  single-identity run reports a hit rate no real deployment would see

## Why this does not run in CI

The plan's phrasing is that mocks make load testing "free, deterministic and
repeatable in CI", and the first two are true. The third is not, for latency:
a shared GitHub runner's timings vary by more than any regression worth
catching, so a latency gate there would fail for reasons unrelated to the code
and get disabled — which is precisely the failure ADR 0047 rejects thresholds
for.

What *would* be worth running in CI is the correctness half — a short
concurrent run asserting zero `FAILED` and zero `UNRECORDED`, which catches
race conditions in the cache, the limiter and the approval store. That is a
real property with a stable pass/fail, and it is named here as the obvious next
step rather than claimed as done.
