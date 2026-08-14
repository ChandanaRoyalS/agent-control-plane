# ADR 0056 — The console is a view of the record, not a second account

**Status:** accepted
**Date:** 2026-08-13

## Context

Task 63: *"Server-sent events streaming tool calls, denials, firewall findings,
breaker state and spend. Minimal styling, no framework ceremony — it exists to
be watched for thirty seconds."*

The obvious build is an event bus. Every interesting call site publishes to it —
`policy.denied` here, a firewall finding there — each carrying whatever shape was
convenient at that line, and an SSE endpoint fans it out. Less code than what
shipped, and one integration point per feature.

It also creates **a second account of what happened.**

This gateway's central claim is that a call it cannot record does not happen
(ADR 0050). The audit chain is the artifact that claim rests on. A live view
built from a parallel stream can disagree with it — a call on the console and
not in the chain, or the reverse — and when it does, an operator has two places
to look and no way to rank them. *The console showed it and `acp audit verify`
does not; which is wrong?* is a question with no good answer at 3am, and the
existence of the question is the damage.

## Decision

### 1. Events come out of the audit write, after the entry is durable

`AuditLog` takes a `published` callback and calls it with each `Entry` it wrote.
Nothing is published for a write that failed.

So a watcher cannot see a call the chain does not have, and cannot see it
*before* the chain has it. The console is a rendering of the record with a
latency of approximately zero, rather than a race against it.

**It renders `Entry.record`, not the `AuditRecord`.** Redaction runs before the
entry is chained, so the mapping is the redacted one and the object is not.
Rendering the object would put on a screen exactly the fields redaction exists to
keep off disk — to an operator who reasonably assumes they are looking at what
was written.

### 2. A callback, so audit does not know a console exists

`AuditLog` imports nothing from `acp.console`. The runtime builds the closure.

Audit is what every other subsystem depends on; an import from it to a demo aid
is the dependency pointing the wrong way, and the first thing to make the audit
tests need a UI.

### 3. It publishes on the event loop, not from the worker thread

`AuditLog.record` runs on a worker thread when the sink blocks (ADR 0053), and
the hub wakes subscribers with an `asyncio.Event` — **which is not thread
safe.** Setting one from a worker thread does not reliably wake the loop and can
leave its waiter list inconsistent.

So `_publish` is called from `arecord` *after* the `await` returns, back on the
loop. The bug this avoids would have been intermittent, load-dependent, and
would have presented as the console dropping events — indistinguishable from the
back-pressure behaviour deliberately built in below.

### 4. A watcher cannot affect the thing it is watching

Three properties, one rule.

- **`publish` is synchronous, non-blocking, and cannot raise.** It runs inside
  `arecord`, between a caller and its response. A browser tab must not be able
  to suspend or fail a request.
- **Each subscriber has a bounded buffer that drops the oldest.** An
  authenticated operator who opens a stream and walks away is otherwise either
  a memory target or a brake on every request. Dropping the oldest is the right
  failure: a live console is for the newest events.
- **Drops are counted and reported to the subscriber that suffered them**, while
  streaming. A trace console that quietly omits events is worse than no console,
  because it is read as complete.

An exception from the callback is caught and logged at WARNING, not ERROR: the
entry is durable and the guarantee held; only the live view missed it.

### 5. Two of the five sources are not in the chain, and are marked

The plan asks for breaker state and spend. Neither is an auditable fact:

- **an upstream's health changing** is not a decision about anybody's call —
  nobody asked for it, nothing was permitted or refused
- **spend** is a running total, and a total is derived rather than something that
  happened. The chain records the calls a total could be computed from and never
  the total.

They are worth watching — an upstream tripping and the console saying so *is* the
demo — so they are streamed as `Source.OBSERVED` and the page renders them
differently, with a legend. **A viewer has to be able to tell what will still
exist tomorrow.**

`observed()` is a named constructor rather than a `TraceEvent(...)` at each call
site, so marking an event live-only is not something a call site can forget.

Two smaller decisions fell out of wiring them:

- **`budget.charged` is published after both draws succeed**, never before. A
  refused call is not spend, and a console counting the attempt would disagree
  with the limiter exactly when somebody is throttled — which is when they are
  looking.
- **the health event carries `time.time()`, not `record.checked_at`.** Health's
  clock defaults to `time.monotonic`, which counts from an arbitrary origin;
  rendering it beside audit's wall clock would put every health event near 1970.
  Two clocks, one timeline, and only one of them means anything to a browser.

### 6. On the admin listener, behind the operator credential

The stream carries **every principal's** activity. An agent that could open it
would read what every other caller is doing.

So it lives beside the approval channel and shares its credential — the same
trust boundary, and a person who may approve a call may certainly watch one. An
agent cannot watch itself for the same structural reason it cannot approve
itself: it cannot address the listener.

With no credential configured the routes are **absent rather than present and
closed** (ADR 0049's argument): a route that exists and always refuses still
tells an unauthenticated caller what this deployment runs.

That boundary is asserted **statically**, by parsing imports: `console_routes`
may be imported by `admin.py` and nothing else. Lesson 10 — bounding which code
can reach a thing beats any number of tests on what that code does with it. A
behavioural test passes for the app it happened to build; this one fails the
moment anybody wires the console anywhere else.

### 7. `fetch`, not `EventSource`

`EventSource` is the browser API built for this and **cannot set request
headers**. The usual workaround is the credential in the query string, which
puts a secret into browser history, into referrers, and into every access log
between the tab and here.

So the page hand-rolls an SSE parser over `fetch()` with an `Authorization`
header. More code in the page, and the correct amount of code in the log. A
token in the query string is **rejected**, with a test, so nobody can quietly
adopt it later.

The wire format stays Server-Sent Events; only the client is hand-rolled.

## Consequences

- `src/acp/console/` — `events` (wire shape), `hub` (fan-out), `app` (routes),
  `page` (one file, no build step, no CDN — a CDN import fails on a laptop with
  no network, which is the machine a demo runs on).
- `AuditLog(published=...)`, `HealthMonitor(on_health=...)`, `_charge(charged=...)`
  — three callbacks, no imports pointing at the console.
- `acp.budget.parties`, the inverse of `account`, so the console displays who
  spent without doing string surgery on somebody else's encoding.
- 32 tests, and the streaming ones drive the endpoint directly.

## The honest cuts

**A disconnected watcher lingers up to `KEEPALIVE_SECONDS`.** The generator
notices a gone client only at a suspension point, and the keepalive guarantees
one every 15 seconds. Shorter would notice sooner and cost more idle traffic;
this is a demo aid and 15 seconds of a dead subscriber costs a deque.

**`TestClient` cannot test the stream**, because closing the client side does not
cancel an infinite server-side generator — the first version of these tests hung
for two minutes. The endpoint is driven directly instead. What that leaves
untested is Starlette's own disconnect handling, which is Starlette's to test.

**No replay.** A console opened now sees the last 50 events and nothing older.
That is deliberate: the chain is the log, `acp audit verify` reads it, and a
second log viewer would be the second account this ADR exists to refuse.

**The page shows raw fields.** No grouping by request, no correlation of a
`policy.allowed` with the `tool_call` that followed it — the audit record carries
no request id today. Worth having; it is a change to the record's schema and
therefore to what an archived chain verifies to, which is not a thing to do for
a UI.

## References

- ADR 0049 — the operator channel is not the agent's channel
- ADR 0050 — an audit record is not a log line
- ADR 0053 — the audit write moved to a thread, which is why decision 3 exists
