# ADR 0032 — Rate limiting: a token bucket per principal

**Status:** accepted
**Date:** 2026-08-10

## Context

Phase 4 defends against runaway spend: an agent — buggy, looping, or compromised
— issuing calls without bound. Policy (Phase 3) decides *whether* a call is
allowed; it says nothing about *how often*. A principal allowed to search may
search a million times a minute, and every one of those is real upstream cost.
The first budget control is a rate limit: a ceiling on how fast a principal may
call, independent of whether each call is individually authorized.

## Decision

**A token bucket per principal, checked in the request path after authorization.**

- **Token bucket.** Each principal has a bucket with a `capacity` (the largest
  burst allowed, and the value it refills toward) and a `refill_per_second` (the
  sustained rate). A call spends one token; a call with no token is refused. This
  is the standard shape because it captures the two things a rate limit needs at
  once — a burst allowance and a steady-state rate — in two numbers and a tiny
  amount of per-principal state.

- **Keyed on the principal's subject.** The unit is the caller: "this principal
  gets this rate", the same identity policy authorizes against. Not per-tool or
  per-upstream for this first control — those are closer to quotas and cost
  accounting, which weight calls differently and come later in the phase.

- **Time is injected, and the core is pure.** The bucket takes `now` as a
  parameter and never reads a clock itself, so the whole limiter is a pure
  function of its inputs — tested by advancing `now` by hand, no sleeping, no
  flakiness. The gateway passes `time.monotonic()` at the one call site; a
  monotonic clock because wall-clock jumps (NTP, DST) must not hand out or
  withhold budget. The bucket is defensive about a clock that moves backwards
  anyway: it adds nothing and never debits on a negative interval.

- **Enforced after policy, keyed on the authorized principal.** The check runs in
  `on_call_tool` *after* `enforce_call`. A call the policy would deny must not
  consume budget — otherwise a caller could exhaust a victim's rate by naming
  tools they cannot use — and there is no point limiting a call that will be
  refused regardless. With no principal (auth off) there is no per-caller budget
  to charge, so the limiter is skipped, exactly as policy enforcement is.

- **Recoverable, with a retry hint.** `RateLimitExceededError` (code `-32050`, a
  new budget range) is `recoverable = True`: unlike a policy denial, the bucket
  refills on its own, so the identical call succeeds once enough time has passed.
  "Wait, then retry" is genuinely different advice from "stop", and the flag is
  what carries it. The error includes `retry_after` seconds — a hint, safe to
  expose because it describes only the limit the caller is already hitting.

- **In-memory, per-process — deliberately.** The buckets live in the gateway's
  memory. That is correct for a single instance and the honest scope of a first
  budget control: it demonstrates the mechanism without dragging in a shared
  store. A distributed limiter (buckets in Redis or similar, shared across
  replicas) is a later extension the `RateLimiter` interface leaves room for —
  `check(principal, now)` is the same signature whether the state is local or
  remote — not something the concept needs to be shown.

## Alternatives considered

**Fixed-window counter** (N calls per calendar minute). Rejected — it allows a
2N burst across a window boundary and has a sharp edge at reset. The token bucket
smooths both for no more state.

**Distributed limiter first.** Rejected as premature. It is the right eventual
answer for a replicated deployment, but building it first would mean standing up
and testing a shared store before the mechanism it backs even exists. The
interface is chosen so it can slot in without reshaping the call sites.

**Limit before authorization.** Rejected — it lets an unauthorized caller burn a
principal's budget (or the gateway's) with calls that were never going to run.
Authorize first; charge budget only for calls that would otherwise proceed.

## Consequences

- New `acp.budget` package: `TokenBucket` and `RateLimiter` (pure, time-injected),
  and `enforce_rate_limit`, the request-path boundary that raises. All unit-tested
  by advancing `now`.
- `RateLimitExceededError` joins the exception taxonomy at `-32050`.
- `build_server`, `build_app`, and `gateway_from_configs` gain an optional
  `limiter`, threaded like `policy`; `gateway_from_settings` builds one from three
  new settings (`rate_limit_enabled`, `_capacity`, `_refill_per_second`),
  defaulting off. `on_call_tool` enforces it after policy. An integration test on
  the real auth path exhausts a bucket and sees the next call refused.
- Quotas, cost accounting (a call costing more than one token — the `cost`
  parameter is already there), and result caching are the rest of Phase 4.

## References

- ADR 0028 — enforce on the real request path (the pattern this follows)
- ADR 0027 — enforcement is the backstop (the sibling policy control it runs beside)
- docs/THREAT_MODEL.md — "Runaway spend → Phase 4", the threat this addresses
