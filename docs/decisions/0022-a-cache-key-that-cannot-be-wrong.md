# ADR 0022 — A cache key that cannot be wrong about who asked

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 27 mints a credential per call and keeps none. That is correct and it is
also two round trips to the authorization server on the request path for every
tool call an agent makes — one to validate the inbound token, one to exchange
it. A single agent turn that fans out across five upstreams becomes five token
requests. A busy gateway becomes a load generator pointed at the one component
whose failure takes down authentication for everything.

So the credentials get held. The question this ADR exists to answer is not
whether to cache — it is what a cache entry is *keyed on*, because that one line
is the difference between a latency improvement and a privilege escalation.

## The failure being designed against

State it plainly, because it is the whole reason this is an ADR and not a
commit message.

What is cached is "the credential for mock-a". So key it on the upstream. Alice
calls; the gateway mints a credential whose `sub` is alice and stores it. Bob
calls the same upstream a second later; the cache hits; bob's request arrives at
mock-a holding alice's credential.

Nothing breaks. The call succeeds. The latency is excellent. Every functional
test passes, because every functional test asks whether the upstream was reached
with a working credential and it was. The only artefact is a line in mock-a's
audit log saying alice read a record bob asked for — and the only person who
would ever find it is an auditor who already suspects something.

The subtler version keys on the *agent*. That feels principled: the caller is
`agent-7`, credentials are per-caller, done. But `agent-7` is the client, not
the user. Alice and bob both reach the gateway through it. Same leak, arrived at
by a more defensible-sounding route, and harder to spot in review because the
key does contain an identity — just not the one that matters.

Both are one word wide. Neither fails a test that anyone would think to write.

## Decision

**The key is the request, not a model of the request.**

An exchange is a pure function of what is sent to the token endpoint: the
subject token, the audience, the resource indicator, and this gateway's own
client credentials (which are constant per process). Two requests that send the
same thing get the same answer back. So the cache key is a SHA-256 digest of the
subject token, plus the audience, plus the resource — and the correctness
argument is one sentence with nothing left to reason about.

**The alternative was to key on the claims** — issuer, subject, actor, scopes —
which is what "cache per principal" naturally suggests and what the previous
section's failures are degenerate cases of. It requires deciding which claims
the authorization server used when deciding what to put in the returned token,
and being wrong about that is invisible. The realm here maps `sub` and `act` and
nothing else. A different server might scope by `azp`, by the subject token's
own scopes, by a claim nobody in this repository has heard of. A key derived
from the request cannot be wrong about any of them, because it does not guess.

It is also strictly safer in the direction that matters. A request-derived key
is at least as specific as any claim-derived one: two different tokens for the
same person produce two entries where a claim key would produce one hit. That
costs an exchange. The opposite mistake costs an identity.

**A digest, never the token itself.** Task 27's invariant is that the inbound
token exists in one place with one reader. A dictionary key is a second place,
and a cache is a structure whose entire purpose is to outlive the request that
created it. SHA-256 of a credential is not a credential and cannot be replayed;
it prints safely into a log line, a traceback or a debugger. Twelve characters
of it are enough to tell two keys apart in a trace and useless for anything else.

**Expiry is judged early, by 30 seconds.** A credential that is live when the
cache checks it and expired when the upstream reads it fails *after* whatever
side effect the call was going to have. The margin already existed on
`ExchangedToken.expired` from task 27, recorded and unused; the cache applies it
rather than comparing timestamps itself.

**Expired entries are dropped, not returned-and-refreshed in the background.** A
caller handed a stale credential cannot tell it apart from a live one, and finds
out at the upstream.

**Single flight, via a per-key lock and a second read inside it.** Concurrent
misses for the same key produce one exchange, not one each. This is the defect
the JWKS cache shipped with in task 22 — twenty concurrent misses, twenty-one
fetches — and here the consequence is worse than wasted work: a burst from one
agent becomes a burst of token requests, and an authorization server that
rate-limits the gateway takes down authentication for the entire estate rather
than slowing one caller. The lock is per key rather than global, because one
global lock serialises every exchange in the gateway behind the slowest one,
which is a latency bug wearing a correctness costume.

**Bounded and least-recently-used, defaulting to 1024 entries.** This is a
security limit before it is a memory one. Unbounded, the cache grows with the
number of distinct (token, upstream) pairs ever seen — which an unauthenticated
attacker cannot influence, but an authenticated one with a token mint can:
obtain tokens in a loop, call once with each, and every entry is retained until
it expires. A bound turns that into eviction of somebody else's entry, costing
an exchange rather than the process. LRU rather than insertion order so a busy
principal does not lose their credential to a burst from a quiet one.

## How this is verified

Three levels, because the failure is invisible at any one of them alone.

**The key, in isolation** (`tests/unit/identity/test_cache.py`): two callers
never share a key; two upstreams never share a key; two resources never share a
key; the key does not contain the token.

**The chain, end to end** (`tests/integration/test_credential_exchange.py`):
alice then bob through one gateway process, asserted at the *upstream* — two
different credentials, and the one bob's call carried names bob. The mock
authorization server was changed to mint a per-caller credential specifically so
this assertion can fail; a mock that returned the same string for everyone would
have made the leak untestable while appearing to test it.

**Against a real server** (`scripts/identity_smoke.py`): the same two questions
asked of Keycloak and the mock upstream fleet over HTTP. The repeat-call check
is only meaningful because Keycloak puts a `jti` in every token — two fresh
exchanges are two different strings, so an identical fingerprint at the upstream
is proof of a cache hit rather than a coincidence.

That last one also catches the quiet failure in the other direction: a key too
*specific* to ever hit returns entirely correct credentials, breaks nothing, and
silently sends every request to the authorization server. No test of correctness
would report it.

## Alternatives considered

**Cache per principal, keyed on `sub`.** The intuitive design, and the one the
whole first half of this document argues against. Its real defect is not that it
is wrong today — with this realm it happens to be right — but that whether it is
right depends on a fact about the authorization server that is not visible from
here and can change without anyone touching this repository.

**Refresh in the background before expiry.** Keeps p99 flat by never making a
caller wait for an exchange. It also means the gateway holds and renews
credentials for callers who have gone away, which is precisely the long-lived
upstream credential task 27 exists to not have — reintroduced as an
optimisation. Deliberately not done.

**A shared cache in Redis.** Correct for a horizontally scaled deployment, and
it puts every live upstream credential in a network service, in its persistence
file, and in whatever backup that service has. The per-process cache costs one
extra exchange per replica per credential. That is a good trade and it stays
this way until something measured says otherwise.

**No cache; keep task 27's behaviour.** Defensible, and it is still reachable —
`cache=None` disables the whole path, which is what most of the test suite runs
in so that it can count exchanges. It is not the default because the cost is
paid by every caller on every call, and the thing it protects against is
protected against properly by the key instead.

## Consequences

**The test task 27 flagged has changed**, which is what it was written for. It
now asserts that *without a cache* every call mints, and the four tests below it
are the argument the change was waiting on.

**Credential lifetime is now visible in the metric rather than only in the
logs.** `acp_credential_cache_total{outcome}` counts hits and misses, labelled
by outcome only — the subject is unbounded cardinality and a metrics label is
the wrong place for anything derived from a credential.

**The health prober still calls upstreams with no credential**, unchanged and
still wrong. It has no caller, so there is nothing to exchange. The right answer
is a client-credentials grant for the gateway's own account, and it needs the
same treatment RFC 8707 got in task 28: measure what Keycloak actually does with
it before writing code that assumes.

**`ACP_AUTH_CREDENTIAL_CACHE_MAX_ENTRIES` is configurable and defaults to 1024.**
Tunable because the right number depends on how many distinct principals a
deployment has; bounded by default because the failure mode of unbounded is
memory exhaustion driven by an authenticated caller.
