# ADR 0006 — Layer resilience as wrappers, in a fixed order

**Status:** accepted
**Date:** 2026-08-06

## Context

The outbound client (ADR 0005) deliberately does one thing: one call in, one
HTTP request out, with every failure classified into the taxonomy. Three
behaviours have to be added around it — retrying recoverable failures (task 13),
failing fast when an upstream is unhealthy, and capping how much of the gateway
a single upstream can occupy (task 14).

They interact, and the interactions are not symmetric.

A client that retries internally cannot be measured correctly by a circuit
breaker placed outside it: three failed attempts of one call arrive as a single
failure, so a breaker configured to open after five failures needs fifteen
actual failures, and takes three times too long to protect anyone.

Retrying and bulkheading interact the other way round. A retry spends most of
its time asleep in backoff. If it holds a concurrency slot while sleeping, the
bulkhead's capacity is consumed by tasks that are not talking to anything.

And the two gateway-side refusals — an open circuit, a full bulkhead — are
recoverable from the agent's point of view and pointless to retry in-process:
the reset timeout is measured in seconds, the backoff in milliseconds, so every
retry is spent waiting on a condition that cannot have changed. Retrying them
converts a fast, honest failure into a slow one, which is precisely the failure
mode the breaker was added to eliminate.

## Decision

Each behaviour is a separate class that satisfies the `Upstream` protocol and
wraps another `Upstream`. They are assembled in exactly one place,
`acp.upstream.factory`, in this order:

```
RetryingUpstreamClient      decides whether to try again, and sleeps
  GuardedUpstreamClient     decides whether to try at all
    UpstreamClient          one call in, one HTTP request out
```

Within the guard, the breaker is consulted before a bulkhead slot is taken.

The taxonomy carries two flags rather than one. `recoverable` is advice to the
agent — this failure is not permanent. `retry_locally` is a decision about the
current request — another attempt within milliseconds could change the outcome.
They agree everywhere except on the gateway's own refusals, which are the whole
reason the second flag exists.

## Alternatives considered

**One resilient client class.** Fewer files, and the layering arguments above
become invisible rather than absent — the ordering constraints still hold, they
are just no longer expressible or testable. It also makes `UpstreamClient`'s own
tests meaningless: "one call, one request" is what they assert.

**Subclassing `UpstreamClient` instead of a `Protocol`.** Each wrapper would
inherit a connection pool and a request path it does not use, purely to satisfy
the type checker. Structural typing says what is actually required — a `config`,
`list_tools`, `call_tool`, `aclose` — and nothing more.

**Bulkhead outside retry.** Simpler to reason about, and wrong: a backoff sleep
would hold a slot it is not using, so a burst of retrying calls would exhaust
capacity while the upstream sits idle.

**Bulkhead before breaker inside the guard.** Then the cheapest possible answer
— "this upstream is down, here is when to come back" — queues behind the most
expensive one. Fast-failing should never wait for capacity.

**Queueing at the bulkhead instead of refusing.** A bounded queue with a short
wait is the common choice. It converts saturation into latency, and latency is
exactly what the caller cannot distinguish from the upstream being slow — so the
agent learns nothing and waits anyway. Refusing says something true in a
millisecond, and `UpstreamOverloadedError` says it in a form the agent can act
on.

**A failure-rate breaker rather than consecutive failures.** The more
sophisticated choice, and it needs a minimum-volume guard that is easy to forget:
without one, a single failed call is a 100% failure rate. Consecutive counting
encodes the volume requirement in its own definition. Revisit if upstreams turn
out to fail intermittently rather than completely — a flapping upstream at a 50%
error rate will never trip a consecutive-failure breaker.

**Counting every exception as a breaker failure.** This is the version that
causes an outage. A malformed response or a rejected request proves the upstream
is *alive*; opening the circuit on those lets an agent sending bad arguments
withdraw a healthy upstream from the catalogue for every other caller.

## Consequences

Each layer is independently testable, and the ordering claims are testable too —
the breaker sees three entries for a three-attempt retry, an open circuit ends
the retry loop after one refusal, a bulkhead rejection leaves the breaker closed.

Adding a layer means writing one class and one line in the factory. Task 18's
health-driven withdrawal reads `GuardedUpstreamClient.snapshot()` and needs no
change anywhere else; task 17's metrics have per-layer counters available rather
than one aggregate.

The cost is indirection: a call now passes through three objects, and a stack
trace is three frames deeper. The factory being the only assembly point is what
keeps that from becoming three different orders in three call sites.

One behaviour is worth stating because it looks like a bug and is not. A call
can open the circuit and then be refused by that same circuit on its own next
attempt, so what surfaces is `UpstreamCircuitOpenError` rather than the timeout
underneath. That is the better error of the two: it carries
`retry_after_seconds`, and the timeout does not.
