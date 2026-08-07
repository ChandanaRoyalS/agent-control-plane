# ADR 0015 — Two identities, not one

**Status:** accepted
**Date:** 2026-08-07

## Context

Everything through Phase 1 runs unauthenticated. The gateway is resilient,
observable, and completely indifferent to who is calling it — which is the
problem the whole project exists to solve, restated: an agent wired into
internal systems holds one service credential per system carrying the union of
every permission any user might need, so a request made for an intern reaches
the same data as one made for the CFO.

Fixing that starts with being able to say who a request is for. Not "which
agent" — that part was never in doubt — but *both*: the human the work is being
done for, and the workload doing it.

## Decision

A `Principal` is a **subject** and an **actor**. The subject comes from `sub`;
the actor from RFC 8693 §4.1's `act` claim, which nests into a chain when a
request passes through more than one party. Bearer tokens are validated against
a JWKS-published key with a fixed asymmetric algorithm allow-list, a required
audience, a required issuer, and a required expiry.

Authentication is enabled by **the presence of configuration**, not by a
boolean. Unauthenticated is represented as `None`, not as an anonymous
principal.

## Alternatives considered

**One identity — just authenticate the agent.** Simpler, and it rebuilds the
exact problem the project is about one layer up. Policy about what may be read
is a question about the subject; policy about which agent may act at all, or
which agent has been compromised, is a question about the actor. Collapsing them
means one of those questions can never be asked again.

**Invent a claim for the actor.** `act` already exists, is specified, nests
properly, and is what the token exchange in task 25 will emit. A bespoke claim
would work today and be unreadable to every other system in the estate.

**An `ACP_AUTH_ENABLED` boolean.** The obvious control, and the wrong one. A
boolean is a thing somebody forgets to set, and the failure mode of forgetting
is a gateway accepting every request while its configuration file claims it
authenticates them. Presence of configuration cannot fail in that direction: you
cannot validate tokens without an issuer. Setting *some* identity settings and
not the others is a startup failure, because half-configured authentication that
silently does nothing is the worst of the three states.

**An anonymous `Principal` for unauthenticated requests.** It reads better at
every call site and it is a trap: an object that looks like a principal to every
caller that forgets to check, and forgetting to check is the entire failure mode.
`None` makes `mypy --strict` refuse to compile the code that forgets — a
guarantee no amount of care provides, and free here because the project already
runs strict.

**Honour the token's own `alg` header.** What a naive verifier does, and the
oldest JWT attack there is. `alg: none` is the crude version. The version that
matters: a JWKS publishes *public* keys, so an attacker takes the published RSA
key, signs a token of their choosing with `HS256` using that key's PEM as the
HMAC secret, and a verifier that honours the header computes the same HMAC and
accepts. The allow-list is asymmetric-only, and a symmetric algorithm is refused
in `TokenPolicy.__post_init__` rather than at verification — a misconfiguration
that can only fail *open* has to be impossible to express, not merely unlikely
to be written. There is a test that forges the token by hand, because PyJWT
refuses to `encode` it and an attacker is not using PyJWT.

**Treat `exp` as optional, since JWT does.** A token without an expiry never
expires. `require` is passed to `jwt.decode` so a missing claim is a rejection
rather than a check that silently does not run.

**Tell the caller why their token failed.** Helpful, and an oracle: expired,
wrong audience, wrong issuer and unknown key are four different probes an
attacker can run one request at a time until they know the configuration. One
message for all of them, with the specific reason in the log where the operator
— who is not the attacker — can read it.

**Use PyJWT's `PyJWKClient` for key fetching.** It does blocking HTTP on
`urllib`, which in an async gateway stalls the event loop for every concurrent
request. The key cache here is `httpx`-based for the same reason ADR 0005 gives
for the outbound client, and PyJWT is used for what it is genuinely good at:
the cryptography and the claim checks.

**Refetch the key set whenever a `kid` is unknown.** The obvious cache-miss
behaviour, and the `kid` comes from the token — which is to say from the
attacker. Unbounded, "send tokens with random `kid`s" becomes an unauthenticated
request amplifier pointed at the identity provider with the gateway paying the
latency. At most one refetch per `min_refresh_interval`; a real rotation is
still picked up, a flood is not amplified.

**Serve a stale key set when the provider is unreachable.** The catalogue cache
already rejected stale-on-error (ADR 0012); here the reason is sharper. A
gateway that keeps validating tokens against keys it can no longer confirm is a
gateway that cannot be told a key was revoked, and revocation is the one thing
key rotation exists to make possible.

**Try every key when a token carries no `kid`.** It works, and it is a signature
oracle costing one public-key operation per key per attempt — an
attacker-controlled multiplier on the most expensive thing the gateway does. No
`kid` is accepted only when there is exactly one key to mean.

## Consequences

**Unauthenticated remains a supported mode, and it is loud.** Every task before
this one ran without authentication, and the gateway has to keep starting while
Phase 2 is unfinished. The trade is noise: a WARNING at startup, and every
request logging `principal: anonymous`, so nobody can read a log and fail to
notice. Making an unconfigured provider a startup *failure* belongs at the end
of the phase, when there is a Keycloak in Compose to configure it against.

**A dependency outage is a 503, not a 401.** Found by a test asserting the
status code rather than by design — the key cache originally raised
`AuthenticationError` for both "your token is bad" and "I cannot reach the
authorization server". Those have different correct responses, and reporting the
second as the first sends every agent in the fleet off to re-authenticate
against a server that is already down. `IdentityProviderUnavailableError` is
deliberately not a subclass of `AuthenticationError`, so the distinction cannot
be lost by an `except`.

**Authentication runs inside the request-context middleware.** Starlette's
`add_middleware` inserts at the front, so it is added *first* to end up
innermost. A 401 that carries no request ID is a 401 nobody can investigate.

**The principal does not carry the token.** Task 25 mints a separate, narrowly
scoped credential per upstream, and the way that guarantee gets quietly broken
is somebody stashing the raw token on the principal "just in case" and a later
layer helpfully forwarding it. There is a test asserting no field of `Principal`
holds it, written before there was any code that could violate the rule.

**The concurrency guard on key refresh is about the key, not the rate limit.**
Written first as a re-check of the refresh interval, which is wrong: on a real
rotation every waiter arrived *because* the key changed, so the interval has
elapsed for all of them and they all fetch. The check that works is whether the
key one was waiting for is now present. Caught by a test that asserted a burst
of twenty concurrent misses produces one fetch, and got twenty-one.
