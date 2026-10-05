# ADR 0066 — An approval is a fact about the fleet, not about a process

**Status:** accepted
**Date:** 2026-10-05

## Context

Pending approvals lived in a dictionary. ADR 0048 said so and called it the
right first cut, and the threat model (section 6.5) ranked it apart from the
other in-memory state for a reason it stated plainly: the rate limiter in
memory makes a replicated fleet *more permissive* by a factor of the replica
count, which is an availability cut, while the approval store in memory makes
a replicated fleet *wrong*. A caller told `input_required` by one replica
retries, the load balancer sends the retry to another, and that replica has
never heard of the token: the call a human just approved is refused as a
forgery. A restart forgets every decision somebody was waiting on. The
startup warning in `build_approval_store` even named the deployment it could
not serve — "a replicated deployment may legitimately answer approvals from a
different process against a shared store" — and then built the store that
could not be shared.

An outside review of the repository listed this second among its gaps, after
the catalogue (ADR 0065). It is the one that stops the control from being
deployable behind a load balancer, which is where a gateway goes.

## Decision

A second `ApprovalStore`, in Redis, selected by one setting.

- **`ACP_APPROVAL_STORE_URL`** — empty keeps the in-memory store, which stays
  the default; a `redis://`, `rediss://` or `unix://` URL puts every held
  request in that Redis, where every replica reads and writes the same record.
  Presence-based like the operator credential and the secret store: a URL is
  not a thing you supply by accident. Any other scheme is refused at load.
- **The gateway refuses to start if the Redis is unreachable.** A configured,
  absent store is worse than none: every gated call would be held in nothing,
  and the first anyone would learn of it is a caller waiting out a TTL for a
  decision that was never stored. Startup is where somebody is watching.
- **The protocol went `async`.** Four methods, one of which now crosses a
  network, and ADR 0053 forbids blocking on the request path. The in-memory
  store's methods are `async` too, with nothing to await — the protocol is one
  shape, not two.
- **One key per token, with a TTL.** `acp:approval:<token>` holds the record as
  JSON, expiring at the request's own expiry **plus a 300-second grace**. The
  grace is what keeps ADR 0048's state machine honest across the boundary:
  "expired" is computed from the record by `flow` and `operator`, so the record
  must outlive its expiry for as long as a late retry or a late operator might
  ask, and get "expired" rather than "no such request" — which are two of the
  seven refusals and are not interchangeable. After the grace, Redis forgets
  it. That TTL is the bound this store has instead of `max_pending`: time,
  enforced by the database, rather than a count enforced by eviction. A flood
  costs the flooder re-asks and costs Redis one TTL of memory; nobody else's
  request is pushed out to make room, so the eviction-order argument of ADR
  0048 has nothing to defend here.
- **`decide` and `consume` are compare-and-set.** `WATCH`/`MULTI` on the key:
  read, check the state is still what the transition requires, write, and
  retry from the read if the key moved underneath. Bounded at five attempts;
  a key that moves five times running is not a race, and the caller gets the
  safe answer for its side — the current record for an operator, "not spent"
  for a retry.
- **`consume` now says whether it spent anything.** It was `-> None` and moved
  any state to `CONSUMED`. That was fine when one process held the dictionary
  and nothing could interleave between `resolve`'s read and its write. With a
  shared store two retries carrying the same approved token, on two replicas,
  both read `APPROVED`; so `consume` moves only `APPROVED` to `CONSUMED`,
  returns whether this call was the one that did, and `resolve` refuses the
  caller that gets `False` with "approval already used". The in-memory store
  keeps the same contract — the protocol is one shape — and a unit test drives
  the race through `resolve` with a store that reports the token spent
  underneath it.
- **Listing is a set, not a scan.** `acp:approval:pending` holds the tokens
  still awaiting a person; `create` adds, a decision removes, and `pending()`
  fetches the members' records in one `MGET`. A `SCAN` would be O(every key in
  the instance), which on a shared Redis is somebody else's data too. A member
  whose record Redis has already forgotten is pruned from the set on read.

## Alternatives considered

- **Sticky sessions at the load balancer.** Pins a caller to the replica that
  holds its token. Fixes the retry and not the restart, and makes a security
  control depend on infrastructure the gateway cannot see or assert.
- **The audit log's SQLite as the store.** Already a dependency, already
  durable. But it is one file per process (section 6.5's other item), so it
  is not shared either; making it shared is a different and larger project.
- **A full Lua script instead of `WATCH`/`MULTI`.** Atomic in one round trip
  and no retry loop. Rejected for now because it puts the state machine in a
  second language, outside mypy and the test suite's reach, to save a round
  trip on a path that already waits for a human.
- **Replicate the in-memory store with a gossip or broadcast.** Every replica
  then holds every record and a partition splits the truth. The approval is
  one fact; it should live in one place.
- **Make the Redis store the default.** The in-memory store is correct for one
  gateway and costs nothing to run, which is how this project is tried. A
  default that needs a second service is a default nobody's first `make up`
  can meet.

## Consequences

- The threat model's section 6.5 loses its first item when the URL is set and
  keeps it, as a statement about the default, when it is not. The audit chain
  being one file per process remains.
- `ACP_APPROVAL_MAX_PENDING` is read and logged as `null` when the store is
  shared; it does not apply. `approval.enabled` names the store (`memory` |
  `redis`).
- A new setting is a minor version under ADR 0058; the surface capture
  changed and was accepted. `redis` is a runtime dependency and `fakeredis` a
  test one; the store's tests run two instances against one fake server,
  which is two replicas against one Redis, and include the double-spend and a
  write stolen inside the `WATCH` window.
- The Redis URL may carry a password, and the gateway logs the store kind,
  never the URL. A deployment should put it in the secret store with the
  other credentials.
- Rate-limit and quota state remain per process (section 6.6). That is the
  availability cut, and it is the next ADR.

## References

- ADR 0048 — the approval state machine, and the dictionary it was first kept in
- ADR 0053 — nothing blocks on the request path
- ADR 0058 — a new setting is a minor version
- ADR 0065 — the review that listed this gap
- `tests/unit/approvals/test_redis_store.py` — two replicas, one Redis
