# ADR 0035 — A result cache key that cannot serve the wrong person

**Status:** accepted
**Date:** 2026-08-11

## Context

Phase 4's last piece is caching the results of idempotent tool calls. The
motivation is ordinary: a read that the same caller makes twice in a minute
should not cost two upstream round trips, two credential exchanges and two
budget draws.

The risk is not ordinary. `CachingUpstreamClient` today caches only
`tools/list`, only when the upstream marks the catalogue `public`, and keys the
entry **on the upstream identity alone** — which is correct precisely because a
public catalogue is the same for everybody. A tool *result* is not. It is
whatever an upstream chose to return to one particular person, and the whole
point of Phase 2 was that different people get different answers.

So this is ADR 0022 again, one layer up and worse. Task 30's bad key would have
served alice's *credential* to bob: serious, but a credential is a thing you can
rotate, an exchange you can count, and an `aud` claim you can check. A bad
*result* key serves alice's data straight to bob with no credential involved,
nothing anomalous in any log, and a latency graph that looks like a win.

There is no existing key here to get wrong. There is a new one to get right.

## The failure being designed against

State it plainly, because it is why this is an ADR and not a commit message.

What is being cached is "the result of calling `crm__search` with
`{"query": "retention"}`". So key it on the tool and the arguments — the obvious
thing, and the thing every general-purpose cache decorator does. Alice searches;
the gateway stores the result. Bob makes the identical search a second later;
the cache hits; bob reads alice's customer records.

Every functional test passes, because every functional test asks whether a
search returns search results, and it does. The upstream's audit log shows one
read, by alice, which is true. Bob's read appears nowhere at all — not in the
upstream's log, because the upstream was never called, and not as an anomaly in
the gateway's, because a cache hit is the system working. **The only artefact of
the breach is its absence.**

The subtler version keys on the principal's `sub` and stops there. That is right
for most deployments and wrong for this one: the gateway's whole model is that a
call is made by an *agent acting for a human*, and an upstream that scopes by
the acting agent — a support bot that sees redacted fields, a research agent
restricted to public records — would have two different answers collapsed into
one entry.

## Decision

**Key on everything that could change the answer, and nothing that could not.**

The key is a SHA-256 digest over a canonical encoding of:

- a **format version tag**, so the encoding can change later without any chance
  of an old entry being read under a new scheme;
- the **subject** — the human the work is for;
- the **actor** — the agent doing it, because an upstream may legitimately scope
  by it, and because including it is the conservative direction;
- the **upstream name** and the **qualified tool name**;
- the **arguments**, canonically encoded: keys sorted, no insignificant
  whitespace, and a refusal to cache at all if they will not serialise.

The correctness argument is one sentence: *two calls that would produce the same
upstream request from the same principal get the same answer, and nothing else
shares an entry.*

**Over-specificity costs a cache miss. Under-specificity costs a disclosure.**
Where the two trade off — should two agents acting for alice share a hit? —
the answer is the one that costs a miss. That is the same rule task 30 settled
on, and it is the only rule that stays right when somebody adds a claim next
year that nobody here has thought about.

**Only tools declared cacheable are cached, and the declaration is
configuration.** A new `config/cache.yaml`, its own file for the reason ADR 0033
gave for keeping cost out of `upstreams.yaml`: cacheability is not a property of
how to reach a tool, nor of who may call it. Absent file or unlisted tool means
no caching, so this is a pure extension — an existing deployment behaves
identically until somebody opts a tool in.

**Idempotence is never inferred.** Not from the tool's name, not from the method,
not from an annotation the upstream supplies. A tool named `search` may write an
audit row; a tool named `get_report` may bill per call; and an *upstream* that
can declare its own results cacheable is an upstream that can make the gateway
serve stale data on request — the same reasoning ADR 0013 applies to tool
descriptions. Somebody with a deployment in front of them says which tools are
safe, in a file that shows up in a diff.

**The cache sits inside the policy check.** This is the reversal, and it is the
part most likely to be got wrong by instinct. Everywhere else in this codebase
caching is outermost — ADR 0006 argues it explicitly, because a hit should cost
nothing: no retry bookkeeping, no breaker check, no bulkhead slot. Here that
instinct is a vulnerability. A result cache consulted before authorization
serves a caller the policy would have refused, and the denial never runs at all.

So the order is **authorize, then consult the cache, then call the upstream**.
A result cache is the one layer whose position is decided by authorization
rather than by latency, and paying the policy evaluation on every hit is the
price of the cache never being a way around it.

**Errors are never stored.** Not a transport failure, not a refused exchange,
and specifically not a result whose `isError` is true. A failed call is a fact
about one moment, and caching it converts a blip into a minute of guaranteed
failure for everybody who shares the key.

**Bounded, LRU, and short.** The same bound as ADR 0022 and for the same reason:
an authenticated caller chooses the keys, so an unbounded cache is a memory
target rather than a cache. TTL comes from the tool's declaration with a low
ceiling — a result cache is for the same caller repeating themselves within
seconds, not for holding yesterday's answer.

**The metric is labelled by outcome and nothing else.** Hit and miss, no
principal, no tool. ADR 0022 made this argument for cardinality; here it is also
a disclosure argument, since a per-principal hit-rate series on a scrape endpoint
is a record of who asked for what and when.

## How this will be verified

**The key, in isolation.** Two subjects never share a key; two actors never
share a key; two upstreams never share a key; two argument sets never share a
key; argument order does not change the key.

**End to end, at the upstream.** Alice calls, bob makes the identical call, and
the assertion is made on what bob *receives* — because that is the only vantage
point from which the leak is a fact rather than an inference about internals.
The mock upstream must return per-principal content, or the leak is invisible
while appearing to be tested. Task 30 learned this the hard way: its
authorization-server mock returned one string per audience, and alice's
credential served to bob would have been the same string.

**As a mutation.** A fourth entry in `scripts/mutate_no_passthrough.py`, or a
sibling harness: drop the subject from the key and require the isolation test to
be the assertion that fails. A test that has never been observed to fail is a
claim about whoever wrote it, and this one guards a silent data breach.

## Alternatives considered

**Key on a digest of the minted upstream credential.** Genuinely attractive —
the credential is precisely what determines what the upstream will return, and
task 30 argued hard that a request-derived key beats a claim-derived one. It
fails here for two reasons. Credentials are minted per call and expire in
minutes, so the hit rate collapses to roughly zero and the cache stops being a
cache. And putting a credential digest into a structure designed to outlive the
request re-opens exactly what ADR 0022 closed.

**Key on `sub` alone.** Simpler, right in most deployments, wrong in the one
this gateway is built for. See above.

**Cache outermost, like the catalogue cache.** Faster on a hit and a way around
the policy engine. Rejected.

**Let the upstream declare its results cacheable.** Moves the decision to the
party with the least reason to be careful about it and the most ability to
abuse it.

**Skip result caching entirely.** Defensible — it is the current state, and the
phase would still have rate limits, costs and quotas. Rejected because the
must-have for Phase 4 is a per-principal cache *with a test proving isolation*,
and the isolation proof is the more interesting artefact of the two. A cache
nobody can be sure about is worth less than no cache; a cache with a mutation
harness pointed at its key is worth more than the latency it saves.

## Consequences

**A denied caller can never be served from cache**, because the cache is behind
the policy gate. This costs a policy evaluation on every hit, which is
in-process work over a validated structure and cheap next to a round trip.

**A policy tightening takes effect immediately; an upstream-side entitlement
change does not.** If alice loses access to a tool, policy refuses her before
the cache is consulted, so nothing stale is served. But if alice keeps the tool
and loses access to some *records inside it*, the gateway cannot see that, and a
cached result may outlive the change by up to its TTL. That is a real residual,
it is why the TTL ceiling is low, and SECURITY.md should say so rather than
leave it to be discovered.

**Cache hits are invisible to the upstream's audit log.** They always are, for
every cache — but for a *result* cache it means the upstream's record of who
read what becomes incomplete by design. Operators who need a complete read trail
at the upstream should not opt that tool in, and `config/cache.yaml` is the
right place for that sentence to live.

**Budget accounting happens on the cache hit, not only on the upstream call.**
Otherwise a caller repeating themselves draws no budget, and the cheapest way to
stay under a quota becomes to ask the same question repeatedly. Cost accounting
(ADR 0033) charges per call; a served-from-cache call is still a call.

## References

- ADR 0006 — resilience as ordered wrappers, and why caching is outermost *there*
- ADR 0012 — honour cache hints within limits (the catalogue cache)
- ADR 0013 — an upstream's self-description is not trusted input
- ADR 0022 — a cache key that cannot be wrong about who asked
- ADR 0023 — prove the invariant, then prove the proof
- ADR 0033 — cost accounting, and why each concern gets its own config file
