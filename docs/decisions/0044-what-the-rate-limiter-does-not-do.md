# ADR 0044 — What the rate limiter does not do, and why each cut was made

**Status:** accepted
**Date:** 2026-08-12

## Context

The plan for this control asked for four things: **sliding-window** rate limits,
**Redis-backed**, **per principal, per tool and per tenant**. What shipped
(ADR 0032) is a token bucket, in memory, per principal only.

Every one of those four is a defensible cut. Only two of them were ever written
down. ADR 0032 declares the Redis cut and the per-tool cut and then rejects a
*fixed-window counter* — which is not the algorithm the plan asked for, and so
does not answer it. Per-tenant is not mentioned anywhere.

That gap matters more than any of the individual cuts. An undeclared deviation
is indistinguishable from an oversight: the next person to read the limiter
cannot tell whether the missing dimensions were considered and dropped or simply
never noticed, and the safe assumption — that they were never noticed — is the
one that gets a control quietly rebuilt. This project's claim is that its
decisions are written down. A decision that only exists as an absence in the code
is not written down.

So this ADR exists to say the unglamorous thing out loud: **the shipped limiter
is narrower than the plan, deliberately, on four counts, and here they are.**

## Decision

**Ship the narrow limiter, and record all four deviations as accepted scope —
with per-tool named as the one worth building next and the shape it would take.**

### 1. Token bucket rather than sliding window over fixed buckets

The plan asked for a sliding window *because burst behaviour at the boundary
matters*. That reasoning is correct and it is aimed at the plain fixed-window
counter, which allows a 2N burst across a reset: N calls at the end of one window
and N at the start of the next, at an instantaneous rate double the stated limit.

A sliding window over fixed sub-buckets fixes that by keeping several small
counters and weighting the oldest by how far it has scrolled out of view. A token
bucket fixes the same problem differently: there is no boundary to burst across,
because there is no window. The bucket refills continuously, so the instantaneous
rate is bounded by `capacity` and the sustained rate by `refill_per_second`, at
every instant rather than at every reset.

Both solve the stated problem. The token bucket solves it with two floats and a
timestamp per principal, where the sliding window needs a counter per sub-bucket
and a decision about how many sub-buckets is enough. The plan named a mechanism;
the requirement underneath it — no burst at a boundary — is met.

What is genuinely lost: a sliding window can answer "how many calls in the last
60 seconds", which is a *reportable* number an operator can put on a dashboard.
A bucket's token count is a budget, not a history. That is a real cost, and it is
the reason to revisit this if anyone ever wants per-principal call-rate
reporting — which is properly the audit log's job (Phase 7), not the limiter's.

### 2. In memory rather than Redis

Already declared in ADR 0032 and restated here for completeness: correct for a
single instance, and `check(key, now, cost)` is the same signature whether the
state is local or remote. The cost is honest and worth naming precisely — with N
replicas the effective limit is N times the configured one, and it resets on
deploy. That is acceptable for a gateway demonstrated as a single instance and
unacceptable for one replicated in production, which is exactly the sort of thing
that should be written down rather than discovered.

### 3. Per principal only — no per-tool limit

ADR 0032 declares this cut ("closer to quotas and cost accounting, which weight
calls differently"), and cost accounting (ADR 0033) partly absorbs it: an
expensive tool costs more tokens, so a principal hammering it exhausts their
budget faster. That is *weighting*, not *isolation* — it cannot express "you may
call anything at 100/s but this one destructive tool at 1/s", which is the actual
per-tool requirement.

**This is the one of the four worth building, and it is cheap.** The limiter is
keyed by a string, not by a `Principal`, so the whole change is the key's shape
plus a per-tool override table — the same `{tool: value}` config shape
`CostTable` and `CacheableTools` already use — and no call-site restructuring:

```
key = subject                 # today
key = f"{subject}\x00{tool}"  # per-tool, when a tool has an override
```

The design question it opens, and the reason it is not a five-minute change: two
limits now apply to one call, so the call must be checked against both, and a
call refused by the second must not have been debited from the first. That is a
real ordering problem — check both, then debit both, never debit-then-check —
and it deserves its own task rather than being smuggled in here.

### 4. No per-tenant limit — because there is no tenant

This is not a cut; it is a missing concept. The identity model (ADR 0015) has
exactly two identities, the human subject and the acting agent, and nothing
above them. There is no tenant claim, no tenant in `Principal`, and no
multi-tenant configuration anywhere in the gateway. A per-tenant limit would
require inventing all of that first.

Inventing it to satisfy one bullet in a limiter would be the wrong order. A
tenant is a policy and identity concept before it is a budget one: it would need
a claim to carry it, a rule for what happens when it is absent, and an answer for
whether policy rules scope to it. Adding a tenant dimension to the rate limiter
alone would produce a limiter that groups principals by a field nothing else in
the system knows about.

So: **per-tenant is out of scope until the identity model has a tenant**, and
naming that dependency is more useful than an unexplained gap.

## Alternatives considered

**Build all four.** Rejected on sequencing, not on merit. Redis and per-tenant
each pull in infrastructure or an identity concept the rest of the system has
not got, and doing them here would make the budget layer the place where a
multi-tenant identity model was invented as a side effect.

**Say nothing and leave ADR 0032 as the record.** Rejected — that is the state
this ADR exists to fix. ADR 0032 answers a question the plan did not ask (fixed
window) and is silent on tenants, so a reader comparing plan to code finds two
unexplained absences and no way to tell deliberate from forgotten.

**Retro-fit per-tool now, since it is cheap.** Rejected for this ADR, accepted as
the next task: the two-limits-one-call ordering above is a correctness question
about when budget is debited, and debiting a budget for a call that is then
refused is precisely the bug ADR 0032's "limit after authorization" rule exists
to prevent. It gets its own change, with its own tests.

## Consequences

- No code change. This ADR records scope, and its whole value is that the
  deviation is now legible: a reader comparing the plan to the limiter finds four
  answers instead of four absences.
- `docs/THREAT_MODEL.md`'s "runaway spend" coverage should be read as *per
  principal, per gateway instance* — a single agent cannot run away, and a fleet
  of replicas multiplies the ceiling.
- Per-tool limits are the named next step, with the key shape and the
  check-both-then-debit-both ordering settled here so the task starts from a
  decision rather than a design.
- Per-tenant limits are blocked on the identity model gaining a tenant, and are
  recorded as blocked rather than missing.

## References

- ADR 0015 — two identities, not one (why there is no tenant to limit by)
- ADR 0032 — rate limiting: a token bucket per principal (the control this scopes)
- ADR 0033 — cost accounting (the weighting that partly substitutes for per-tool)
- docs/THREAT_MODEL.md — "runaway spend", the threat this control addresses
