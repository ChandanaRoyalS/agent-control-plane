# ADR 0053 — Durability is a trade; blocking the loop is a bug

**Status:** accepted
**Date:** 2026-08-13

## Context

Task 61: *"`py-spy` to find sync work on the event loop, pool sizing and
serialization costs. Publish the before and after; the delta is a better story
than the final number."*

Task 60's harness found the sync work before a profiler was attached, and found
it more conclusively than a profiler could have.

Two runs, identical in every respect but one environment variable:

| | fsync on | fsync off | speed-up |
|---|---|---|---|
| throughput | 44.7 req/s | 114.5 req/s | 2.56x |
| served p50 | 222.4 ms | 94.2 ms | 2.36x |
| **listed p95** | **2819.4 ms** | **223.9 ms** | **12.59x** |

The first two rows are the price of durability. **The third row is a bug.**

`tools/list` writes no audit record. `on_list_tools` filters a catalogue by
policy and returns; it never touches the sink. It has no disk write of its own
to wait for, and it was 12.6x slower at p95 anyway — because
`FileAuditSink.append` is a synchronous method calling `os.fsync`, and it was
invoked from an `async def` handler. **On the event loop thread.**

While one request's record reached the platter, every other request in the
process stopped, whether or not it was writing anything.

## Decision

### 1. The write moves to a thread and stays awaited

`AuditLog.arecord` hands `record` to a worker thread via
`anyio.to_thread.run_sync` and awaits the result. `record` itself is unchanged
and still public, for the CLI, the tests, and any caller with no loop to
protect.

**The fail-closed guarantee is untouched**, and that is the constraint every
other option was measured against: the calling request is still suspended until
its entry is durable, and still raises `AuditUnavailableError` when it cannot
be. ADR 0050's central claim — *a call this gateway cannot record does not
happen* — survives verbatim. What changes is who else pays.

### 2. Serialised by a `CapacityLimiter(1)`, not made parallel

`Chain.append` mutates sequence state. Two threads inside it would read the
same `prev`, write two entries claiming the same predecessor, and produce a file
that fails verification — **trading the exact property the chain exists to
provide for throughput nobody asked for.**

So audit writes still happen one at a time. That is not a compromise on the
fix; it is the whole shape of it. The win is not parallel writes, it is that
*the loop is free while the one write happens* — so requests doing no audit
write stop queueing behind it, and requests doing upstream I/O overlap with the
disk instead of waiting for it.

A `CapacityLimiter` rather than a separate lock because it is the same object
`to_thread.run_sync` already accepts: one concept doing both the serialising
and the thread-slot accounting.

### 3. Not `fsync=false`

The obvious "fix" is the switch task 60 added for measurement. It is not a fix;
it is the trade, taken. A gateway whose central argument is that unrecorded
calls do not happen does not get to lose the record to a power cut because a
laptop benchmark looked bad.

`ACP_AUDIT_FSYNC=false` stays available for a deployment that has decided
otherwise — and now it can decide with a number instead of a feeling.

### 4. `_token_from` becomes async, because it performs I/O

The credential exchange recorded its audit entry inside a synchronous parsing
helper. Making the write async made that a type error, which is the type system
reporting something true: **a function that writes to a durable log is not a
parser.** One caller, already async, so the change costs nothing and the
signature stops lying.

### 5. `anyio` becomes a declared dependency

Five runtime modules import it and it was in no dependency list, arriving
transitively through `mcp`. `pyproject.toml` already carries the rule, two
lines above where the entry should have been: *"If you import it, declare it:
arriving transitively through `mcp` is a fact about today's resolution, not a
contract."*

Found while adding the sixth importer. The rule was right and nobody had
applied it to the modules that predated it.

## What this is expected to buy, stated before measuring

Written down first, so the measurement can disagree:

- **`listed` p95 recovers almost entirely.** It was pure head-of-line blocking;
  nothing about `tools/list` needs the disk.
- **Throughput rises, but stays below the `fsync=false` number.** Audited calls
  are still serialised behind one `fsync` at a time — the loop is freed, the
  disk is not made faster.
- **`served` p50 improves**, because upstream round-trips now overlap with disk
  waits instead of alternating with them.
- **`fsync=false` remains faster than `fsync=true`**, and the gap is now the
  honest price of durability rather than the price of durability *plus* a
  scheduling defect.

If throughput reaches the `fsync=false` number, something in this reasoning is
wrong and the follow-up is to find out what.

## Measured — three repetitions, alternating

Single runs disagreed with each other, so the measurement was repeated: six
runs, alternating on/off, no rebuild between them (`make load-ab`).

| | fsync on | fsync off |
|---|---|---|
| throughput | 56.7 req/s [49.7–66.2] | 120.1 req/s [115.4–126.2] |
| **listed p50** | **15.1 ms** [14.6–15.6] | 83.5 ms |
| **listed p95** | **35.7 ms** [30.4–40.4] | 160.5 ms |

**Durability costs 2.14x of throughput.** ADR 0050 §8's declared cost, measured.

Against the state before this change: **`listed` p50 191.1 → 15.1 ms (13x) and
p95 2819.4 → 35.7 ms (79x)**, with a standard deviation of 0.4 and 4.1 ms. Both
deltas are orders of magnitude beyond the run-to-run spread, so they hold
whatever the noise. The "before" figures are single runs, so the *throughput*
improvement is real in direction and is not claimed as a number.

### `listed` proves the fix twice

It is **15.1 ms with `fsync` on and 83.5 ms with it off** — 5.5x faster in the
*slower* configuration. `tools/list` is pure CPU, so its latency now tracks
**event-loop contention**, which is what it should track: with `fsync` on the
gateway runs at 57 req/s and the loop is comparatively idle; with `fsync` off it
runs at 120 and the loop is busy. Before the fix it was 191 ms, tracking a disk
it never touches.

### And a methodological finding

Throughput rose monotonically across reps in **both** configurations. The
machine warms; any single run understates, and the first understates most.

One earlier figure — 41.9 req/s, taken immediately after a 40-second image
build — sits *below* the 49.7–66.2 range this same code produces over three
runs. It looked like a regression and was an outlier. It would have entered this
ADR as a fact if it had not been repeated.

**A number without a repetition count is a sample wearing a decimal point.**

### Scoring the predictions, finally

| prediction | verdict |
|---|---|
| `listed` p95 recovers almost entirely | **right** — 79x, tight variance |
| throughput rises, stays below `fsync=false` | right — 56.7 vs 120.1 |
| `served` p50 improves | **wrong** — ~300 ms against 222 ms, though the before is n=1 |
| `fsync=false` stays faster | right — 2.14x |

Two corrections came out of being wrong: decision 1a (offload only when the
sink blocks), and the repetition discipline above.

## The honest cuts

**`py-spy` was not run.** The plan names it, and a flamegraph would be a good
picture. A controlled A/B is *stronger evidence* than a profile — it shows
causation rather than where time was spent — and it had already named the
function. Attaching `py-spy` to the gateway container needs `SYS_PTRACE` and a
compose change, which is real setup for confirmation of something already
established. Declared here rather than skipped silently, and the capability
change is a five-line patch whenever the picture is wanted (task 68's blog post
is the likely reason).

**No group commit.** Databases amortise this exactly here: let N concurrent
writers share one `fsync`. It would raise *audited* throughput, which this
change deliberately does not. It is the obvious next optimisation and it is not
in this task, because it changes the durability story (an entry is durable when
its batch syncs, not when it is written) and that deserves its own decision.

**The thread pool is anyio's default.** Sized for the process, not tuned for
this. With a limiter of 1 the audit path uses one slot, so the tuning question
is whether *other* `to_thread` users exist — today there are none.

**One process, one chain, one writer.** Unchanged from ADR 0050. A replicated
fleet still writes independent chains, and serialising per process says nothing
about serialising across them.

## Alternatives considered

**Buffer and flush in the background.** Rejected: the caller would proceed
before the record was durable, which is the guarantee, not an implementation
detail.

**Drop `fsync`.** Rejected — decision 3.

**A dedicated writer thread with a queue.** Equivalent for correctness, more
machinery: fail-closed requires the caller to await the outcome anyway, so the
queue would need a per-item future. `to_thread` plus a limiter is the same
thing with less code.

**`aiofiles` or an async file API.** Rejected: `os.fsync` has no async form on
Linux that avoids a thread — the libraries wrap a thread pool. Wrapping it
directly is fewer layers and the limiter is explicit.

**Leave it and document it.** Rejected. Task 60's numbers make this the largest
measured defect in the project, and it is one afternoon.

## Consequences

- `AuditLog.arecord`; `record` unchanged and still public.
- `gateway/server.py`'s three audit helpers and `_chain` become async and are
  awaited; `predispatch._record` likewise; `exchange._token_from` becomes async.
- `anyio` joins `[project.dependencies]`.
- Six new tests, two of which assert the *cause* rather than the symptom: the
  write does not run on the caller's thread, and the loop keeps ticking during
  a slow write. **Both were mutation-checked** — and the second one failed that
  check on its first version, which asserted "20 ticks happened" and would have
  passed against the unfixed code, because the ticks all happen either way,
  merely later. What discriminates is how many have run *at the moment the
  write completes*.

## References

- ADR 0050 §8 — `fsync` per entry, declared then measured
- ADR 0052 — the harness whose per-outcome grouping made this visible
- `perf/README.md` — the A/B, and the before/after
