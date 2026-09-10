# ADR 0054 — An overhead number is meaningless without its switch settings

**Status:** accepted
**Date:** 2026-08-13

> **Note (2.0.0).** `scripts/patch_*.py` were removed in 2.0.0 (see the README's *How this was built*); the references below are historical.

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

## Measured

Full tables, both runs and the ablation ladder: [`perf/README.md`](../../perf/README.md).
Repeated here only where the ADR's own reasoning depends on it.

| row | | direct p50 | gateway p50 | added p50 | multiple |
|---|---|---|---|---|---|
| cache miss | budgets **off** | 5.3 ms | 38.1 ms | +32.8 ms | 7.19x |
| | budgets **on** | 3.6 ms | 24.4 ms | **+20.7 ms** | 6.72x |
| cache hit | budgets **off** | 6.8 ms | 22.8 ms | +16.0 ms | 3.35x |
| | budgets **on** | 4.3 ms | 13.7 ms | **+9.4 ms** | 3.19x |

**The register earned its place on the first execution.** It reported
`ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED` unset on a stack that was
supposed to have them — the sixth instance of one failure (ADR 0055), and a
defect that would otherwise have been published as a fact about the system. The
run was repeated on the fixed stack before v1.0.0 quoted anything.

**Two controls were added and every number went down.** Not because a token
bucket makes a gateway faster: between the two runs the machine was quieter, and
that difference is larger than the controls being measured. Which is the finding:
**the multiple is portable and the milliseconds are not.** Between-session
variation is at least 13.7 ms — 42% of the first run's headline — so any
absolute figure from this harness is a fact about one laptop on one afternoon.
The multiples moved by 0.07x and 0.16x.

### Two predictions, both scored, both lost

**Decision 4 predicted the cache-hit row would show *negative* overhead.** It
does not, and it is not close: 22.8 ms against 6.8 ms. A cache hit removes the
upstream round trip and nothing else — about 6 ms against a mock. The gateway
still authenticates, evaluates policy, screens, frames, and waits for an audit
record to reach the disk. **Its own fixed cost is larger than the entire thing
the cache eliminates.** The row stays with the smaller true claim attached: the
*difference* between the rows is what the cache is worth, 15.3 ms.

The prediction is not wrong in general — against an upstream that takes 200 ms,
a 16 ms hit wins by an order of magnitude. It is wrong *here*, and here is what
was measured and therefore all that may be said.

**The ablation predicted `fsync=off` would drop the fixed cost into single
digits.** It drops it by 5.6–8.8 ms, roughly a third. The audit `fsync` is the
single largest attributable component and it is not most of the cost.

### What the 17.8 ms is made of

| | |
|---|---|
| the direct call itself — network and the mock | 5.2 ms |
| **the audit `fsync`** | **5.8 ms** |
| everything else, individually unresolved | ~6.8 ms |

Authentication, policy evaluation, the audit write minus its `fsync`, the
pre-dispatch check, the framework and the extra hop are all in that last row and
**this instrument cannot separate them.** Each is smaller than the variation
between two container restarts, and each rung *requires* a restart because these
are start-up settings. More samples inside a run does not help; only repeating
the whole ladder does, which is what `--repeat` is for.

The ladder also caught an error in itself: the first version computed one
resolution from the control's p50 and applied it to the p95 column, producing
steps that were negative *and* above the floor — impossible as costs, since
removing work cannot make a thing slower. A floor that cannot be violated is
worth more than a floor that is usually right.

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
