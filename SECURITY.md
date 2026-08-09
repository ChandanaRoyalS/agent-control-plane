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
  asserted by a test rather than claimed by a comment, and breaking it is the
  most serious finding this project could receive.
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

## Supported versions

None yet. There has been no release, so there is nothing to backport to. Once
there is, this section will say which versions receive fixes.
