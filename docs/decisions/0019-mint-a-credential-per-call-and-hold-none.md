# ADR 0019 — Mint a credential per call, and hold none

**Status:** accepted
**Date:** 2026-08-09

## Context

This is the task the phase was built toward. Everything from 22 to 26
established *who* is asking. None of it changed what the upstream is handed.

The problem, stated once more because it is the reason the project exists: an
agent wired into internal systems holds one credential per system, and that
credential carries the union of every permission any user might need. The same
request reaches the same data whether it was made for an intern or the CFO. The
upstream cannot tell them apart, because nothing in what it receives says.

RFC 8693 token exchange is the standard answer. The gateway presents the
caller's token to the authorization server and asks for a different one: same
subject, audience narrowed to a single upstream, lifetime in minutes.

## Decision

**A credential is minted per call and the gateway holds none.** There is no
long-lived upstream credential anywhere in the process, because there is nothing
to hold — the token is made when the request is about to leave and is expired
long before anyone could find it. Caching is task 30 and will have to argue for
itself against this.

**The exchange goes back to the issuer that minted the subject token.** The
token's `iss` selects the registration and the request goes to *that*
registration's endpoint. `token_endpoint` is a field on `IssuerRegistration`
next to the key set and the audience, for the reason ADR 0016 gave: they are one
indivisible thing. One shared endpoint would mean presenting one authorization
server's token to another's — the mix-up attack, reached by a convenience.

**The token endpoint is discovered, not configured.** It comes from the metadata
document that RFC 8414 §3.3 has already proved belongs to this issuer, so it
inherits that proof. `ACP_AUTH_TOKEN_ENDPOINT` exists only for the case where an
explicit `ACP_AUTH_JWKS_URL` skipped discovery, and startup refuses to run with
exchange on and any issuer lacking one.

**A failed exchange fails the call.** The alternatives are to call the upstream
with no credential — a gateway that has silently stopped enforcing the thing it
exists for — or to forward the caller's own token, which is the passthrough this
phase exists to prevent. Neither is a degradation worth having.

**Presence of client credentials is the switch.** No `ACP_AUTH_EXCHANGE_ENABLED`,
for the reason there is no `ACP_AUTH_ENABLED`: a credential cannot be forgotten
and still have the feature appear to work. Half a credential is a startup
failure.

**An upstream with no `audience` is a startup failure once exchange is on.** A
gateway that credentials four upstreams and reaches the fifth with nothing is
worse than one that credentials none, because the hole is the only part nobody
is watching.

## The inbound token now has to exist somewhere

Task 22 established that `Principal` carries no token, so that nothing holding
an identity could accidentally forward a credential. Exchange needs the token
anyway — RFC 8693 sends it as `subject_token`.

Weakening the principal was the obvious move and the wrong one. The token
instead lives in its own context variable, `_subject_token`, with its own name
and one reader: `acp.identity.exchange`. That turns the invariant task 31 must
prove from a claim about a data structure passed everywhere into a claim about
one call site:

> the value in that variable is sent to the token endpoint of the issuer that
> minted it, and to nowhere else.

Nothing *prevents* another module reading it. What there is, is a name that
makes doing so obvious in a diff — which is the honest description of most
security boundaries inside a single process.

## A bug this found

The circuit breaker counts any failure the taxonomy marks `recoverable`. An
unreachable authorization server is correctly marked recoverable. So before this
task's test existed, one identity-provider outage would have opened **every**
upstream's circuit simultaneously, withdrawn the entire estate's tools from
every agent's catalogue, and left logs blaming five servers that were answering
perfectly.

The exchange happens before a byte is sent to the upstream. `counts_as_failure`
now excludes `CredentialExchangeError` explicitly, alongside the gateway's own
refusals and the upstream's deliberate rejections.

Worth noting how it was found: not by running anything, but by writing the test
`test_an_identity_outage_does_not_open_the_upstream_circuit` and then reading
the predicate to see whether it would pass. The general form — *when adding a
new error type, read every place that classifies errors* — is cheaper than
discovering it during an outage.

## Alternatives considered

**Put the credential in a wrapper layer, like retry and the breaker.** ADR 0006
composes resilience as ordered wrappers, so a `Credentialed(...)` layer looks
consistent. It is not: a credential minted outside the cache is minted for
answers that are never sent, and one minted outside the retry is reused across
attempts that may outlive it. The client is the only layer that knows a request
is actually about to leave the process.

**Give `UpstreamClient` a concrete dependency on `acp.identity`.** It would make
every transport test need an authorization server, and put an identity import in
the one package that should be usable without one. `Credentials` is a structural
`Protocol` in `acp.upstream.protocol` taking a name and an audience — never a
principal, never a token. The client cannot forward an inbound credential
because it is not holding one.

**Retry a failed exchange inside the upstream's retry budget.** The authorization
server is a different dependency with different availability characteristics.
Borrowing an upstream's backoff for it means an identity outage is charged to a
service behaving perfectly. `retry_locally` is false; caching (task 30) is the
real mitigation.

**One error type with an instance-level `recoverable`.** `recoverable` is a class
attribute throughout this taxonomy. `CredentialProviderUnavailableError` is
therefore a subclass — unlike `IdentityProviderUnavailableError`, which is
deliberately *not* a subclass of `AuthenticationError`. The difference is what a
shared handler would do: there, `except AuthenticationError` sends a 401 and
turns a dependency outage into a login storm. Here no such handler exists, and
both mean "no credential, so the call cannot proceed".

**Let the health prober's calls go through exchange too.** It has no principal,
because no user asked for it. The correct answer is a client-credentials grant
for the gateway's own service account; that needs a second grant type and
belongs with task 30. Until then a probe reaches an upstream uncredentialed —
a real gap, safe only because a deployment with exchange configured also sets
`ACP_AUTH_REQUIRED`, so every request-path call has a principal.

## Working with Keycloak, and where it is narrower than the RFC

Two constraints found by reading the documentation before writing the realm,
rather than by watching an exchange fail:

**The subject token must name the requester in its `aud`.** Keycloak refuses
otherwise. So `acp-agent`'s tokens carry two audiences: `http://localhost:8080/mcp`,
which is what this gateway checks, and `acp-gateway`, which is what Keycloak
requires to permit the exchange. Both are in `aud`, and an audience check passes
on membership.

**Keycloak's `audience` parameter filters; it does not add.** The audiences a
token *can* carry come from the requester's client scopes, and the parameter
narrows that set. So `acp-gateway` carries an audience mapper per upstream, and
the exchange names one. This is worth knowing before task 28, where it is the
difference between `resource` doing what RFC 8707 says and doing nothing.

**Keycloak names its exchange target by client ID, not by URI.** RFC 8707 allows
a URI. That is why the realm defines an `acp-upstream-mock-a` client that exists
purely to be named. Whether Keycloak also accepts a `resource` parameter is task
28's question; if it does not, the deviation gets an ADR the way task 23's did.

**Standard token exchange V2 emits no `act` claim.** RFC 8693 §4.1's actor claim
is what makes a delegation chain readable — "alice, via the gateway" rather than
just "alice". Keycloak's V2 does not produce it, so the realm adds it with a
hardcoded claim mapper on `act.sub`. Static, and correctly so: the actor is the
gateway for every token it exchanges. It is a workaround, it is labelled as one,
and the smoke test asserts it rather than assuming it.

## Consequences

**The mock upstreams report what credential they were handed**, at
`/debug/credential`. It is the only vantage point from which the no-passthrough
invariant is observable from *outside* the gateway process — everything else
asserts it by inspecting a request the gateway built, using the same code path
under test. They return a fingerprint and the decoded claims, never the token: a
demo that prints a working bearer token to a terminal has taught the reader
something they should not have, and the interesting part was never the token.

**`identity_smoke.py` grew five checks**, and one of them is the point of the
whole phase: the credential the upstream received has a different fingerprint
from the one the caller presented.

**`tools/call` rather than `tools/list` in those checks.** With the health
prober running, the catalogue cache is permanently warm and a `tools/list` may
never reach an upstream at all — the same property that made the fan-out
invisible in traces until probing was turned off.

**The first CI run of those checks failed, and the gateway was right.**
`tools/call` routes on `Mcp-Name` as well as `Mcp-Method`, and a server verifies
both against the body (ADR 0008). The smoke script sent no `Mcp-Name`, so the
request was rejected before any upstream was reached — and five checks all
reported "no credential" for a call that was never made.

Two things are worth taking from that. The failure was *plural and identical*,
which is the signature of one cause upstream of all of them rather than five
bugs. And the same request shape put through the mock fleet's own validator
returns `-32020` HEADER_MISMATCH, so the property ADR 0008 bought — mocks that
enforce the specification rather than agreeing with our client — caught the
client this time, which is the direction that matters least often and proves
most.

**Nothing is cached, and a test asserts it.** Two calls produce two exchanges.
When task 30 changes that, the test that has to change is that one —
deliberately, with the cache key argued over, rather than a behaviour nobody
noticed. Getting that key wrong is a privilege escalation with excellent
latency.
