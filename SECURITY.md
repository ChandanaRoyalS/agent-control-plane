# Security

## Status

**This project has not been security reviewed. Do not run it in front of
anything real.**

That is not boilerplate. The Agent Control Plane is a security control by
design — it sits between AI agents and the systems they are allowed to touch —
and a security control that has not been reviewed is a single point of failure
wearing a reassuring name. It is built in the open, phase by phase, as a study
in doing this properly; it is not a product and has no operational track record.

## Reporting a vulnerability

Open a [security advisory](https://github.com/chandanaroyal719-bot/agent-control-plane/security/advisories/new)
rather than a public issue, and please allow time for a fix before disclosing.

If you would rather not use GitHub advisories, open a normal issue containing
*no detail* — just "I have a security report" — and I will follow up privately.

There is no bounty. There is a commitment to reply, to say plainly whether
something is in scope, and to credit you unless you would rather not be.

## What is in scope

Anything that lets a caller do something the gateway is supposed to prevent:

- Authenticating as a principal you are not, or as no principal at all.
- Crossing credentials between authorization servers — a token issued by one
  server being judged by another's rules ([ADR 0016](docs/decisions/0016-bind-every-credential-to-its-issuer.md)).
- Reaching an upstream, tool or resource the resolved principal is not entitled
  to (from Phase 3 onward, when there is a policy engine to bypass).
- Causing the gateway to forward an inbound token upstream. This invariant is
  asserted by a suite rather than claimed by a comment — every wrapper
  composition, every protocol method and every credential shape, with each
  request searched whole rather than one header inspected
  ([ADR 0023](docs/decisions/0023-prove-the-invariant-and-prove-the-proof.md)).
  A mutation harness breaks it three ways on every pull request and fails the
  build if the suite does not notice. Breaking it is still the most serious
  finding this project could receive, and a report that defeats *both* the sweep
  and the static one-reader check is the most interesting one it could receive.
- Injected instructions surviving result screening (from Phase 5, when there is
  screening to defeat).
- Unauthenticated denial of service that costs the attacker meaningfully less
  than it costs the gateway — for example turning a request into an amplified
  load on the identity provider.

## What is deliberately not defended against

Stated here so that "we did not think of it" and "we decided against it" are
distinguishable. The full reasoning is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

- **A compromised identity provider.** If the authorization server can be made
  to mint arbitrary tokens, everything downstream follows. The gateway binds
  each issuer to its own keys and audience so a *second* server cannot speak for
  the first, but it cannot detect a server lying about its own users.
- **An identity provider reached over plain HTTP, when an operator has asked for
  that by name.** `ACP_AUTH_INSECURE_ISSUER_HOSTS` is empty by default and
  widens the plain-HTTP exemption to hosts listed in it. Anything on the path to
  such a host can replace the key set and mint tokens the gateway will accept.
  It exists because the alternatives people reach for — widening the loopback
  set, or disabling certificate verification — are broader and quieter, and
  every entry is logged at every start ([ADR 0018](docs/decisions/0018-one-issuer-string-from-every-vantage-point.md)).

- **An exchanged credential the gateway cannot read.** Every credential minted
  for an upstream is checked to be scoped to that upstream and no other
  ([ADR 0020](docs/decisions/0020-check-the-scope-you-were-granted.md)). That
  check reads the token's `aud`, so an authorization server issuing *opaque*
  reference tokens defeats it — the gateway logs `auth.scope_unverifiable` and
  proceeds, because refusing would rule out a whole class of provider for a
  property it cannot observe either way.

- **Anything that can read the secret key file, or the running process.** The
  encrypted store ([ADR 0021](docs/decisions/0021-one-backend-behind-a-seam.md))
  reduces many secrets to one key; it does not remove that key. Root on the box,
  a core dump, or read access to the key file gets everything. The decrypted
  values live in memory for the process's lifetime and are not wiped, because
  Python offers no way to reliably zero a `str` and a `del` would be theatre.
  The claim is "fewer places for a credential to be lying around", not "safe".

- **Exchanged credentials living in gateway memory for their lifetime.** Since
  [ADR 0022](docs/decisions/0022-a-cache-key-that-cannot-be-wrong.md) the
  gateway holds each minted credential until shortly before it expires, so a
  core dump or a debugger attached to the process yields live upstream
  credentials for whoever was recently active. Task 27's stronger claim — that
  the process holds nothing reusable — now holds only across the credential's
  few minutes of lifetime. The cache is bounded, per process, never written to
  disk and never shared over a network, and background refresh was rejected
  precisely so the gateway does not hold credentials for callers who have gone
  away.

- **A cached result outliving an upstream entitlement change.** Since
  [ADR 0035](docs/decisions/0035-a-result-cache-key-that-cannot-serve-the-wrong-person.md)
  a tool result may be held for up to its configured ttl, capped at 300 seconds.
  If a principal loses access to the *tool*, policy refuses them before the cache
  is consulted and nothing stale is served. But if they keep the tool and lose
  access to some records *inside* it, the gateway cannot see that change, and a
  held result may be served for the remainder of its ttl. The ttl ceiling is that
  exposure window, which is why it is bounded in code rather than in
  configuration. Cache hits also do not reach the upstream, so an upstream's own
  record of who read what becomes incomplete for any tool opted in — which is a
  reason not to opt one in.

- **A malicious operator.** Anyone who can change the configuration, the schema
  baseline or the policy files can change what the gateway permits. The controls
  here are arranged so that doing so leaves a reviewable trail — the schema
  baseline is a committed file, the container mounts `config/` read-only — not so
  that it is impossible.
- **The model's judgement.** The gateway constrains what an agent *can* do. It
  does not make the agent's decisions good ones.
- **Traffic the gateway never sees.** An agent holding a direct credential for
  an upstream bypasses this entirely. That is a deployment property, not
  something code here can enforce.

## Design notes relevant to security

The decisions with security consequences are written up as ADRs, with the
alternatives that were rejected and why:

- [0008](docs/decisions/0008-validate-requests-against-the-spec.md) — validate against the specification, not against our own mocks
- [0010](docs/decisions/0010-metrics-on-a-separate-listener.md) — the metrics endpoint is a reconnaissance report, so it gets its own loopback listener
- [0013](docs/decisions/0013-schema-drift-is-a-security-control.md) — a changed tool description is an attack, not an ops event
- [0014](docs/decisions/0014-ship-one-image-and-compose-the-rest.md) — the mock upstreams are stripped from the production image; `config/` is mounted read-only so a compromised gateway cannot silence its own drift alarm
- [0015](docs/decisions/0015-two-identities-not-one.md) — asymmetric algorithms only, because a JWKS publishes public keys and an attacker can sign HS256 with one
- [0016](docs/decisions/0016-bind-every-credential-to-its-issuer.md) — issuer, audience and key set are one indivisible registration
- [0017](docs/decisions/0017-let-the-gateway-tell-clients-where-to-authenticate.md) — the one unauthenticated path is derived from the document served there, not from an allow-list; and why publishing the authorization servers is a reconnaissance cost worth paying where publishing the upstreams is not
- [0018](docs/decisions/0018-one-issuer-string-from-every-vantage-point.md) — an issuer is an identity and not an address; and why the plain-HTTP escape hatch is narrow, named and logged rather than absent
- [0019](docs/decisions/0019-mint-a-credential-per-call-and-hold-none.md) — the gateway holds no upstream credential; the inbound token reaches exactly one module, whose only destination is the issuer that minted it
- [0020](docs/decisions/0020-check-the-scope-you-were-granted.md) — RFC 8707's parameter is a request, not a guarantee; the control is checking the credential that came back names one upstream and no other
- [0021](docs/decisions/0021-one-backend-behind-a-seam.md) — an encrypted store turns many secrets into one key and says so; references live in config, values never do
- [0022](docs/decisions/0022-a-cache-key-that-cannot-be-wrong.md) — a credential cache keyed on the request rather than on claims, because keying it on the upstream serves one caller's credential to the next and passes every functional test
- [0023](docs/decisions/0023-prove-the-invariant-and-prove-the-proof.md) — the no-passthrough invariant swept across every path, two static alarms that fail when a new path appears, and a mutation harness in CI that breaks the invariant on purpose to prove the test can fail
- [0035](docs/decisions/0035-a-result-cache-key-that-cannot-serve-the-wrong-person.md) — a result cache key that cannot serve the wrong person, and why this one cache sits *inside* the policy check rather than outside it

## Supported versions

None yet. There has been no release, so there is nothing to backport to. Once
there is, this section will say which versions receive fixes.
