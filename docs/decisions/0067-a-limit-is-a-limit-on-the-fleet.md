# ADR 0067 — A limit is a limit on the fleet, not on a process

**Status:** accepted
**Date:** 2026-10-05

## Context

The rate limiter (ADR 0032) and the quota (ADR 0034) each kept their state in
a dictionary, and each said so: "correct for a single gateway, with a shared
store across replicas left as a later extension". The threat model (section
6.6) stated the consequence without softening it — a replicated fleet
multiplies every limit by the number of processes. Configure a burst of sixty
and run three replicas and a payer has a hundred and eighty, apportioned by
whatever the load balancer does. A limit that scales with the attacker's luck
is not the limit that was configured.

ADR 0066 moved approvals to Redis because the per-process version was *wrong*.
This is the other half of section 6.5's distinction: the per-process budgets
were not wrong, they were *permissive*, and the same reviewer who listed the
approval store listed them beside it. The two now share a store and not a
mechanism, and this ADR is mostly about why the mechanism differs.

## Decision

A second keeper of budget state, in Redis, selected by one setting — and a
name for the step the gateway was already taking.

- **`Budgets.charge(payer, cost, mono, wall)`** is the request path's one
  question to the budgets: may this payer spend this much now, and if so,
  spend it. It was four calls in the gateway — check the bucket, check the
  window, debit the bucket, debit the window — with a comment that nothing
  awaits between them. That ordering is ADR 0044 §3's "check both, then debit
  both", and across replicas it is only true inside something the server runs
  without interleaving. So the step is a protocol, `LocalBudgets` implements
  it with the four calls it always was, and `RedisBudgets` implements it as
  one script. `build_server` takes either; given a limiter or a quota it
  wraps them in the local keeper, so nothing that built a gateway before
  changes.
- **`ACP_BUDGET_STORE_URL`** — empty keeps the in-memory limiter and quota; a
  Redis URL builds the shared keeper *instead of* them, because a bucket in
  this process beside a shared one would be a second, unshared budget. The
  URL is validated at load, the store is pinged at startup, and the gateway
  refuses to start if it is unreachable. **Independent of
  `ACP_APPROVAL_STORE_URL`**, deliberately: shared approvals fix a correctness
  bug and cost a round trip per *held* call; shared budgets fix a permissive
  limit and cost a round trip per *charged* call. A deployment may want the
  first and not the second. Both may name the same Redis.
- **One Lua script, one round trip.** Refill the bucket to ``now``, read the
  window's tally, check both against the cost, debit both or refuse. Redis
  executes a script atomically, so two replicas charging one payer at the
  same instant are serialised by the server. ADR 0066 chose `WATCH`/`MULTI`
  over Lua and gave its reason — the state machine in a second language,
  outside mypy and the suite. The trade flips here because the access
  pattern flips: an approval key moves a handful of times in its life, a
  payer's bucket moves on every call, and an optimistic transaction on a hot
  key is a retry loop under exactly the load a rate limiter exists for. The
  script is forty lines, the arithmetic is `TokenBucket`'s and
  `QuotaCounter`'s, and the contract tests run every case against both
  keepers so the Lua cannot drift from the Python unnoticed.
- **The in-memory classes remain the specification.** `TokenBucket` and
  `QuotaCounter` are unchanged; the script reimplements them. Start full,
  refill at the rate to the capacity, never remove tokens for a backwards
  clock; windows clock-aligned at ``floor(now / window)``. The refusal
  carries the same three numbers (`retry_after`, `remaining`, `limit`) from
  either keeper.
- **One clock.** The in-memory limiter refills on a monotonic clock so a
  wall-clock step cannot hand out or withhold burst. Replicas share no
  monotonic clock. The shared keeper refills on the wall-clock reading the
  caller already passes for the window. A step on one replica's clock
  misgrants or withholds at most one capacity, once, on that replica; the
  elapsed-time guard still never removes tokens for a backwards step. The
  protocol keeps both readings so the local keeper loses nothing.
- **Time is the bound.** A bucket key expires when the bucket would be full,
  because a missing bucket *is* a full one — "start full on first sight",
  kept by the database. A tally key names its window
  (`acp:budget:quota:<payer>:<index>`) and expires when the window ends, so a
  window's spend is a value that expires rather than a field that resets.
  Neither needs `max_principals`; nobody is evicted to make room, which was
  the eviction argument of ADR 0044 with nothing left to defend.
- **Configuration travels with the call.** Capacity, rate, limit and window
  are script arguments, not stored. A change takes effect on the next call,
  and two replicas with different settings are a misconfiguration the store
  does not hide — whichever answers, answers with its own numbers.

## Alternatives considered

- **`WATCH`/`MULTI`, as for approvals.** Rejected above: the hot-key retry
  loop. A limiter that thrashes under load is a limiter that fails exactly
  when it is needed.
- **Sliding-window log in a sorted set.** More precise than a token bucket
  and the usual Redis idiom. But the in-memory limiter is a token bucket, the
  refusal's `retry_after` is a bucket's, and a fleet running a different
  algorithm per keeper would be two controls wearing one name.
- **Local buckets with a shared correction** (each replica charges locally
  and reconciles). Fast, and approximately right; "approximately" is the word
  the threat-model item already used for the bug.
- **One setting for both stores.** Simpler. It would also force a round trip
  per call on a deployment that wanted only its approvals shared, and would
  make a later move of either store a breaking change to the other.
- **Redis `TIME` inside the script** rather than the caller's clock. One
  clock for the whole fleet, and no test can set it. The caller's wall clock
  is what the window already used, and `fakeredis` lets a test advance it.

## Consequences

- Section 6.6's last item is closed when the URL is set and remains, as a
  statement about the default, when it is not. The per-tool and per-tenant
  gaps in that section are untouched.
- Every charged call pays a Redis round trip on the request path — sub-
  millisecond on a loopback or same-host Redis, more over a network. This
  is the first per-call network hop the gateway adds on its own account, and
  the overhead harness (ADR 0054) does not yet measure it; a run with the
  store configured is the obvious next record for `make overhead-record`.
- A new setting is a minor version under ADR 0058; the surface capture
  changed and was accepted. `redis` was already a runtime dependency; `lupa`
  joins the dev group so `fakeredis` can run the script.
- A gateway with the URL set and neither budget enabled warns and does not
  open the store. A gateway with the URL set and the store down does not
  start.
- `RateLimiter` and `QuotaCounter` are no longer the only way to be charged;
  anything that reads budget state directly for display would read only the
  local keeper's. Nothing does today.

## References

- ADR 0032, 0034 — the token bucket and the fixed window, as specified
- ADR 0044 §3 — check both, then debit both
- ADR 0053 — nothing blocks on the request path
- ADR 0066 — the approval store, and why it chose the other mechanism
- `tests/unit/budget/test_redis_budgets.py` — the contract, against both keepers
- `tests/integration/test_budget_wiring.py` — two gateways, one bucket
