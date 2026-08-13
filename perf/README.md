# Load and latency measurement

Phase 8. `perf/scenarios.py` decides what to ask and how to read the answer;
`perf/locustfile.py` is the Locust wiring. Task 61 profiles what this finds and
task 62 measures the gateway's overhead against a direct upstream call.

## Running it

```bash
make up            # the stack must be up: gateway, mocks, Keycloak
make load          # 30 seconds, 20 users
make load-long     # 5 minutes, 100 users
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
  `config/costs.yaml`, and whether `ACP_AUDIT_FSYNC` is on
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
