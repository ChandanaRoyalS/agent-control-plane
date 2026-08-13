# ADR 0052 — A load test that does not average its own answer

**Status:** accepted
**Date:** 2026-08-13

## Context

Phase 8 opens with task 60: *"Locust against the mock fleet, reporting
throughput and p50/p95/p99. Mocks make load testing free, deterministic and
repeatable in CI."*

The Locust part is an afternoon. The interesting question is what a number
produced by this harness would actually *mean*, because a load test is a
measuring instrument, and **an instrument nobody calibrated produces numbers
with the authority of measurement and the content of a guess.**

Three things about this gateway make the default answer wrong.

## Decision

### 1. Report latency per outcome, never in aggregate

A default Locust run gives you a p95 across every request it made. For this
gateway those requests are not one population:

| what happened | how far it got |
|---|---|
| refused at the routing header | no body parsed, no policy evaluated (ADR 0043) |
| held for a person | policy evaluated, no upstream, no cache |
| served from cache | policy, budget, cache — no upstream, no screening |
| served from upstream | the whole path, including firewall screening |

**A p95 across those is a statement about the task mix, not about the
gateway.** Worse, it *moves when the policy changes*: gate one more tool and
the aggregate improves, because held calls are fast. A performance number that
improves when you add a control is a number pointing the wrong way.

So `perf.scenarios.Outcome` has seven values, latency is collected per outcome,
and the report prints the mix beside the timings. The numbers are then
comparable between runs, and each one describes a single path.

### 2. An error rate counts defects, not defences

The instinct is 2xx-is-success. Under that rule a policy denial, a rate-limit
refusal and a held approval are all "errors", and **the error rate gets worse
the better the gateway defends itself.** Nobody would keep such a dashboard for
long, and the way people fix it is by removing the controls from the test.

Six of the seven outcomes are the gateway working. Only `FAILED` — a transport
error, a 5xx, an unparseable body, or an MCP error code the harness does not
recognise — is a defect. An *unknown* error code counts as `FAILED` on purpose:
quietly bucketing a novel error as "working" is how a real regression is
absorbed into a healthy-looking report.

Two outcomes get printed as warnings rather than data:

- **`THROTTLED` non-zero** means this run measured the rate limiter. The
  latencies then describe a queue as much as a gateway, and saying so is the
  difference between a result and a misreading.
- **`UNRECORDED` non-zero** means the audit sink could not keep up and those
  calls did not happen (fail-closed, ADR 0050). This is the number Phase 8
  exists to put a figure on: `fsync` per entry bounds throughput to the disk's
  sync rate, declared in ADR 0050 §8 and never yet measured.

### 3. The decisions live in a module with no Locust import

`perf/scenarios.py` — the mix, the request shapes, the classifier, the
percentile function — imports nothing but the standard library and is unit
tested (25 tests). `perf/locustfile.py` is gevent, the user model and the
reporting hook.

The same split as `acp.audit.cli` vs `acp.cli`, for the same reason and with
the same payoff: the part that can be silently wrong is the part a test can
reach. **Misread one response shape and the harness manufactures an error rate
that looks exactly like a finding about the gateway** — the most expensive kind
of wrong number, because somebody acts on it.

The classifier reads *both* the HTTP status and the body, because the two
layers refuse differently: a pre-dispatch refusal is an HTTP 403 with no
JSON-RPC frame at all, while a handler-level denial is a 200 with an error
object inside. A classifier that read only one would report the same deployment
differently depending on which layer happened to refuse — and the fast path is
the one a real client hits most.

### 4. The harness sends `Mcp-Name`, because a real client does

The pre-dispatch fast path abstains when the routing headers are missing
(ADR 0043). A load generator that omits them silently benchmarks the slow route
and publishes the numbers as though they described the fast one.

Task 55 found exactly this omission in the *test* suite, where it made two
denial tests pass without ever reaching the code they named. Here it would be
worse: the output is a number somebody quotes.

### 5. It refuses to run against a chaos-injecting mock fleet

`CHAOS_MODE` is a process-wide environment variable on the mocks — the thing
that makes the resilience tests possible — and it survives whatever experiment
set it. A run with it on measures the injected latency and reports it as the
gateway's.

That is the project's most repeated failure shape (valid input, no error,
silently different behaviour), and the symptom here would be a p99 written into
a README. So the harness checks and refuses. It reads the *host's* environment
and cannot see a value baked into a running container, so this is a cheap guard
rather than a proof — and the README says to `make down && make up` when a
number looks wrong.

### 6. One token per simulated user, and two principals

Minting a token per request would make this a Keycloak benchmark with a gateway
attached; Keycloak is the slowest thing in the compose stack by an order of
magnitude.

Alternating alice and bob matters more than it looks. The result cache, the
rate limiter and the quota counter are all keyed per principal (and now per
tenant, ADR 0051), so a single-identity run exercises one bucket and one cache
partition, and reports a hit rate no real deployment would see.

### 6a. Amendment — one token per *principal*, not per user

Decision 6 said "one token per simulated user", and the harness's own first run
proved that wrong within a second of starting.

Twenty greenlets logging into the same account simultaneously, against a realm
configured `bruteForceProtected: true`, is structurally a password-guessing
attack. Keycloak locked the account and answered `invalid_grant: Invalid user
credentials` — deliberately indistinguishable from a wrong password, which is
why the first diagnosis looked like a credentials bug. Half the fleet never
sent a request.

The principle in decision 6 was right and the scope was wrong: minting per
*request* would make this a Keycloak benchmark, and minting per *user* was the
same mistake moved to startup, where it was harder to see. **One token per
principal, per process, behind a lock** — two logins per run.

And a second bug in the same six lines: the principal was chosen with
`id(self) % 2`. CPython object addresses are 16-byte aligned, so that
expression is **0 for every object ever allocated**. Every simulated user was
alice; the two-principal argument in decision 6 described something that never
happened, and nothing errored. It is the project's most repeated failure shape
— valid input, no error, silently different behaviour — this time inside the
measuring instrument, which is the worst place for it, because the output is a
number somebody quotes.

**The report was confident through both.** It now prints how many users
actually started of how many were requested, and warns when those differ. A
number's provenance is part of the number.

### 6b. The first 3 seconds are discarded

Cold connection pools, a cold JWKS cache and a cold result cache are real
costs, and they are not the steady-state latency this report claims to
describe. In a 30-second run they land squarely in the p99 — the number people
quote. The window is fixed, small, and the discarded count is printed, because
a discarded window nobody can see is a number quietly improved.

### 6c. An upstream failure is not a gateway defect

The first 20-user run produced one `FAILED`, and it was an upstream error code
— the gateway correctly reporting that a mock could not keep up under load.

Calling that a defect points the reader at the wrong component, and it breaks
decision 2's own claim that `FAILED` is "the only bucket that should be zero":
push hard enough and an upstream will always go slow. So the `UpstreamError`
family gets its own bucket, and a non-zero count prints a warning that says
what it actually means — **this run measured the mock fleet as much as the
gateway**, which is a statement about the experiment rather than about a bug.

The family is enumerated, not inferred from the sign of the code, so a novel
error still lands in `FAILED` where somebody has to look at it.

### 7. It does not run in CI, and the plan says it should

The plan's sentence is that mocks make load testing "free, deterministic and
repeatable in CI". The first two are true. **The third is false for latency**:
a shared GitHub runner's timings vary by more than any regression worth
catching, so a latency gate would fail for reasons unrelated to the code and
then get disabled — precisely the failure ADR 0047 rejects thresholds for, and
lesson 15's *a false positive is how a control gets switched off*.

Recorded as a deviation from the plan rather than quietly skipped, because an
undeclared deviation is indistinguishable from an oversight.

**What would be worth running in CI is the correctness half** — a short
concurrent run asserting zero `FAILED` and zero `UNRECORDED`, which catches race
conditions in the cache, the limiter and the approval store. That is a real
property with a stable pass/fail. Named as the next step, not claimed as done.

## What the harness measured, and what it found

Three runs, same mix, same machine.

| | 10 users* | 20 users | 20 users, fsync off |
|---|---|---|---|
| throughput | 14.2 req/s | 44.7 req/s | **114.5 req/s** |
| served p50 | 11.2 ms | 222.4 ms | 94.2 ms |
| served p95 | — | 903.9 ms | 386.7 ms |
| listed p95 | — | **2819.4 ms** | **223.9 ms** |

\* half the fleet had died to a Keycloak lockout; see 6a.

**`fsync` per audit entry costs 2.56x of throughput** — ADR 0050 §8's declared
cost, now measured.

**And `tools/list` was 12.6x slower at p95 while writing no audit record at
all.** It has no disk write to wait for. It was waiting for other requests',
because `FileAuditSink.append` is a synchronous `os.fsync` called from an
`async def` handler — on the event loop every request shares.

That distinction is the whole value of grouping by outcome (decision 1). An
aggregate p95 would have shown one number moving and left the cause invisible;
a per-outcome table showed a bucket that *cannot* be paying the cost paying it
anyway, which names the mechanism without a profiler.

Durability is a trade. Head-of-line blocking is a defect. Task 61 fixes the
second without giving up the first.

## The honest cuts

**No CI gate at all yet**, per decision 7 — so a performance regression is
caught by somebody running `make load`, which means by somebody remembering.

**The numbers describe one machine.** Everything runs on one host through
Docker's network stack against mocks that answer in microseconds. That is what
makes the gateway's own work visible — and it means nobody may quote a p99 from
this harness as "the Agent Control Plane's latency". Task 62's overhead
measurement, which compares against a direct upstream call on the same machine,
is the only figure here portable to somebody else's.

**Cache hits and misses are not distinguished in the report.** They cannot be,
from outside: the response is byte-identical either way, which is the cache's
whole job. Inferring it from latency would be reading the thing being measured
as though it were an input. The mix contains both on purpose, and
`acp_result_cache_total{outcome}` already counts them from inside.

**Single-process load generation.** Locust's distributed mode is one flag away
and untested here; on one laptop the generator competes with the gateway for
cores, which flatters nothing but must be said.

**This is not a saturation test, and the first version's wording implied it
was.** At 20 users with a 0–50 ms wait and a ~30 ms round trip, offered load is
bounded well below what the gateway can serve, so these numbers describe
*latency under light load*. That is exactly what task 62 needs. A capacity
figure needs hundreds of users and a zero wait time, measured deliberately
rather than inferred from this run.

## Alternatives considered

**A plain asyncio + httpx driver.** Tempting: no new dependency, more precise
control, and it would run in CI. Rejected because the plan names Locust and
because the web UI and distributed mode are real capabilities — but the
scenario module is deliberately driver-agnostic, so task 62 can reuse it from a
direct-to-upstream client with no Locust in the picture.

**Counting refusals as failures.** Rejected — decision 2.

**One aggregate p95.** Rejected — decision 1. It is the number every load test
reports and the one that means least here.

**Running against a real upstream.** Rejected: the network would hide the
gateway's own work, which is the only thing this harness can see.

## Consequences

- New `perf/` package: `scenarios.py` (pure, tested), `locustfile.py`
  (wiring), `README.md` (methodology and how to read the output).
- `make load` (30s, 20 users) and `make load-long` (5m, 100 users), added by
  `scripts/patch_makefile_load.py` — an asserted patch, because `Makefile` is a
  drift file.
- `locust` joins the `perf` dependency group. CI installs it and never invokes
  it.
- 25 unit tests over the classifier, the request shapes and the percentiles.
- Percentiles are **nearest-rank**: an interpolated p99 is a weighted average of
  two samples — a plausible latency **no request actually experienced** — in a
  report whose entire purpose is to say what requests experienced.

## References

- ADR 0043 — authorize on the routing headers (why `Mcp-Name` is sent)
- ADR 0047 — a baseline, not a threshold (why there is no CI latency gate)
- ADR 0050 §8 — `fsync` per entry, declared and not yet measured
- ADR 0051 — per-tenant keys (why the run uses two principals)
