# ADR 0063 — Durability, and the bounds nobody enforced

**Status:** accepted
**Date:** 2026-09-10

## Context

Four findings from the same review, and they share a shape: a limit this
repository had *written down* and had not *made true*.

**1. Two writers corrupt the audit chain silently.** ADR 0050 says "one process,
one file" and nothing enforced it. `FileAuditSink.__init__` calls `recover(path)`
and opens the file in append mode; two processes doing that both recover the
same head and then interleave entries from it. Every entry after the first
collision carries a `prev` that does not match the line above it — the chain is
corrupt from that moment, `acp audit verify` reports tampering on a file nobody
touched, and **nothing fails at write time**. An integrity claim that can be
broken by starting the service twice is a claim about a deployment convention.

**2. The approval store loses decisions on restart.** ADR 0048 names this first
in its own limits and calls it what it is — a *correctness* cut, not the
accuracy cut ADR 0044 makes for budgets. A gateway that answered
`input_required`, took a person's yes and then restarted tells the caller no for
a call that was approved.

**3. Eviction crossed tenants.** `InMemoryApprovalStore.create` dropped the
globally-oldest record regardless of tenant *or state*. So 256 calls from any
principal whose policy gates a tool pushed every other tenant's pending
approvals out — a cross-tenant denial of service costing one authenticated
caller nothing. And decided or consumed records, which are history rather than
pressure, competed for the same room as live ones.

**4. Budget maps grew without limit.** `RateLimiter._buckets` and
`QuotaCounter._spent` create an entry per principal and never remove one —
including from `retry_after` and `remaining`, which only read. The result cache
(512) and the credential cache were both bounded for exactly this reason. These
two were the ones where the key is chosen by whoever holds an issuer.

## Decision

**An advisory exclusive lock on the chain file.** `flock(LOCK_EX | LOCK_NB)`,
taken after the handle opens and before the recovered head is trusted, so no
second writer can be recovering the same tail concurrently. A second process
gets a `ConfigurationError` naming the file. `flock` releases when the process
dies, which is the behaviour wanted after a crash: the next start takes the lock
rather than finding a stale one nobody can clear. It does not span NFS
reliably — a limit for the threat model, not something to pretend about.

**A SQLite approval store**, behind the `ApprovalStore` protocol that was
written for exactly this. One file, `PRAGMA synchronous=FULL`, WAL so the
operator's listing does not block the request path's insert, and every mutation
inside `BEGIN IMMEDIATE` so decide-and-consume cannot interleave with another
worker reading the same row. Unset config keeps the in-memory store and logs a
warning naming the consequence.

**Eviction is per tenant, and sweeps spent records first.** One tenant filling
its own store costs its own users a re-ask — the cost the bound was always meant
to impose — and costs a stranger nothing.

**Budget maps are bounded at 10,000 principals, least-recently-used.** Eviction
*refunds* whoever held the entry, which is why this is safe and why the order
matters: the evicted principal is the one who has not called for longest, whose
bucket was closest to full anyway.

## Alternatives considered

**Redis or Postgres for approvals.** Better for a replicated deployment, and
correct in a way SQLite is not: two gateways with two files still cannot resolve
each other's tokens. Rejected for now because it adds a service to a system
whose entire deployment story is one container, and because it solves a
*different* sentence. "A restart loses every pending decision" and "two replicas
cannot share one" are separate cuts; this closes the first and leaves the second
where it was, in the threat model, said plainly.

**A lock file beside the chain rather than `flock` on it.** Slower and weaker,
and for the reason the sink's own docstring already gives about reopening by
path: it opens a window in which the path can be swapped, and it leaves a stale
file after a crash that somebody has to know to delete.

**Refuse to start without a durable approval store.** Considered and rejected:
the in-memory store is a legitimate configuration for a deployment whose policy
gates nothing, and `gates_calls` already decides whether the store exists at all.
The warning names the consequence; the configuration is one line.

**A TTL sweep on the budget maps instead of a size bound.** Needs a clock and a
task, and bounds nothing in the interval — a burst of a million distinct
subjects inside one window is exactly the shape being defended against.

## Consequences

Starting two gateways against one audit file now fails loudly instead of
corrupting the chain. That will surface in any deployment that was accidentally
doing it, which is the point.

`ACP_APPROVAL_STORE_FILE` is a new setting and unset behaves as before, with a
warning. The compose stack does not set it, because the compose stack
demonstrates the gateway rather than operating it — noted so the next reader
does not mistake that for an oversight.

The rate limiter's eviction makes its accounting *approximate under pressure* in
a new way: a principal evicted and re-seen gets a full bucket. That is strictly
more generous than the truth, which is the safe direction for a limiter whose
own ADR already calls its numbers approximate, and it takes ten thousand
distinct principals to reach.

What would make us revisit: a deployment that genuinely needs two gateways
sharing one chain, or one whose approval volume outgrows a single SQLite file.
Both are the shared-backend conversation, and both should start with the
question this ADR deliberately did not answer.
