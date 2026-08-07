# ADR 0016 — Bind every credential to the server that issued it

**Status:** accepted
**Date:** 2026-08-07

## Context

Task 22 validates a bearer token against one authorization server. Task 23's
brief is to close the **authorization server mix-up** attack, and the task list
names RFC 9207 as the mechanism.

RFC 9207 does not apply here, and it is worth being exact about why. It adds an
`iss` parameter to the *authorization response* — the redirect that carries an
authorization code back to a client. It defends a client that talks to several
authorization servers against being tricked into sending a code obtained from
one to the token endpoint of another. This gateway is a **resource server**: it
receives bearer tokens and never runs a redirect flow, so the parameter RFC 9207
defines never reaches it. Implementing it literally would be a citation, not a
control.

The *threat* absolutely applies. At a resource server it takes a different
shape, and it only exists once more than one issuer is trusted — which is what
"cannot be crossed" in the brief implies.

## The attack this actually closes

Trust two authorization servers. Collect their published keys into one pool.
Verify an incoming token's signature against whichever key in the pool matches.
*Then* read `iss` and apply that issuer's registration.

A token genuinely signed by the partner's key, claiming `iss` of the corporate
directory, passes. The signature is valid — it really was signed by a trusted
key — and every decision afterwards is made against the wrong server's
registration. The partner can mint corporate principals at will, with no forged
signature anywhere.

The same crossing has a quieter, attacker-free variant: a `jwks_url` pasted into
the wrong environment file, so the gateway verifies tokens with one server's
keys while believing they came from another.

## Decision

**A registration is indivisible.** Issuer, audience, key set and permitted
algorithms are configured together and used together, as one `IssuerRegistration`
value.

**`iss` selects the registration before any rule is applied.** The claim is read
from the unverified payload, chooses exactly one registration, and the signature
is then verified against *that* registration's keys with *that* registration's
issuer and audience.

**Discovery verifies the issuer-to-keys binding** rather than trusting it.
`jwks_url` is optional; when absent it comes from the authorization server's
metadata, and RFC 8414 §3.3 requires that document to name the same issuer it
was fetched for.

## Why reading an unverified claim is safe here

It looks wrong, and the reason it is not is worth stating precisely, because the
argument is the whole design.

You cannot know which key set to verify against without first knowing who the
token says issued it. At that moment nothing has been checked. The safety does
not come from the peek being trustworthy — it comes from what happens next.
Having selected registration `A` *because the token said `A`*, the signature
must verify against `A`'s keys and `iss` must equal `A`'s issuer. A token that
lies selects a registration whose keys will not verify it. A token that tells
the truth gets the rules that belong to it.

The broken version is the same three facts in the other order: verify first
against anything, read `iss` after. That is a pool of keys, and a pool of keys
has no opinion about which server a token came from.

## Alternatives considered

**Implement RFC 9207's `iss` authorization-response parameter.** It would be a
no-op: nothing in this gateway processes an authorization response. Citing the
RFC while doing nothing it specifies is worse than not citing it, because it
makes a reviewer believe a control exists.

**Keep a single issuer and declare the mix-up out of scope.** Defensible today
and a trap tomorrow. The crossing hole opens the moment somebody adds a second
server, and it opens *silently*, in a configuration file, with no code change to
review. The same argument as caching `public` only in ADR 0012: build the shape
that is correct now and still correct later.

**One key pool with per-issuer rules applied afterwards.** The natural
implementation and the vulnerability described above. It is natural because a
key pool is what a JWKS cache looks like if you stop thinking about who
published it.

**Normalise issuers before comparing — trim trailing slashes, lowercase hosts.**
Removes the commonest configuration papercut and defeats the mechanism. RFC 8414
§2 compares issuers as strings; normalising means this gateway's notion of "the
same authorization server" differs from the specification's, and two systems
disagreeing about identity is the entire subject. The papercut is handled by an
error message that names the trailing-slash case explicitly.

**Fall back to the only registration when a token has no `iss`.** Works with one
issuer, and becomes a cross-issuer hole the day a second is registered —
silently, in a file nobody was editing at the time.

**Require `jwks_url` and skip discovery.** Simpler, and it leaves nothing
anywhere checking that the key set belongs to the issuer. An explicit URL is
still permitted, because some servers publish no metadata and refusing them
would be a purity the deployment cannot act on — but it logs a warning at every
start, since skipping the check should be a decision somebody made rather than
one inherited.

**Follow redirects when fetching metadata.** Convenient, and it undoes the
check: a document reached by redirect is served from somewhere other than where
the issuer's identity says it should be, which is the property being verified.

**Try the next well-known URL when a document declares the wrong issuer.** A
server that answered *and named somebody else* has not failed to answer.
Continuing would be looking for a server willing to agree with us. Only
transport-level failures fall through to the next candidate.

**Discover lazily, on first use.** Then an issuer whose metadata contradicts its
own identity surprises the first request instead of stopping the deployment.
Discovery runs at startup, before a port is bound, like every other
configuration check in this project.

**Allow plain HTTP issuers.** RFC 8414 §2 requires `https`, and it is right to:
metadata fetched over HTTP can be rewritten in transit, and this document
decides which keys the gateway trusts. Loopback is exempted, because a Keycloak
in `docker compose` on a laptop is genuinely reachable only at
`http://localhost:8080` and refusing it means nobody can run the demo.

## Consequences

**`ACP_AUTH_JWKS_URL` is now optional and discouraged.** Task 22 required it;
this makes it the escape hatch rather than the norm. That is a settings change
one commit after shipping the settings, which is the right time to make it.

**Two configuration sources, mutually exclusive.** Environment variables for one
server, `ACP_AUTH_ISSUERS_FILE` for several. Setting both — or a global
`ACP_AUTH_JWKS_URL` alongside the file — is a startup failure. A shared key URL
across several issuers is the crossing this ADR exists to prevent, spelled as a
config option.

**`build_token_validator` became async**, because discovery touches the network.
It runs inside `gateway_from_settings`, which was already async.

**Both well-known URL forms are tried.** RFC 8414 *inserts* the segment
(`https://host/.well-known/oauth-authorization-server/realms/acp`); OpenID
Connect Discovery *appends* it (`https://host/realms/acp/.well-known/openid-configuration`).
Real servers implement one, the other, or both. A client that knows only one
fails against half the world for a reason that looks like a network problem.

**An unregistered issuer is refused without naming the registered ones.** Which
authorization servers an organisation trusts is a useful map for somebody
choosing where to attack, and an unauthenticated caller can ask as often as they
like.
