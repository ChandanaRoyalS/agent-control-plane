# ADR 0061 — A tenant label is mandatory once there are two issuers

**Status:** accepted
**Date:** 2026-09-10

## Context

ADR 0051 made a tenant an *issuer registration* rather than a claim, and that
boundary is right: a label the gateway stamps after verification cannot be
forged by a token, and `tenancy.py` falls to `DENY_ALL` for an unknown label
rather than to the default policy.

What ADR 0051 did not do is make the label **mandatory**. It is optional, and
`config/issuers.yaml.example` — the file an operator copies — registered two
identity providers with no labels at all:

```yaml
issuers:
  - issuer: https://idp.corp.example/realms/acp
    audience: agent-control-plane
  - issuer: https://idp.partner.example/
    audience: agent-control-plane-partner
```

Both principals then carry `tenant=None`, and nothing downstream of the
validator looks at which issuer a principal came from:

| what | keyed on | sees the issuer |
|---|---|---|
| policy rule matching | `principal.subject` | no |
| result cache | `(tenant, subject, actor, upstream, tool, args)` | no |
| budget account | `[tenant, subject]` | no |

So the partner identity provider mints `sub: cfo@corp`, and that principal
receives the corporate CFO's policy grants, the corporate CFO's cached results
and the corporate CFO's budget. ADR 0051's own text describes this collision —
"two identity providers each have an alice" — and closed it only for
deployments that opted in.

**Isolation that has to be opted into is isolation the shipped configuration
does not have.** The review that found this did not need to construct an exotic
deployment; it read the example file.

## Decision

Two changes, because there are two distinct collisions.

**1. Between tenants: the label is mandatory as soon as there is a second
issuer.** One issuer owns its whole subject namespace and there is nothing to
collide with, so `tenant` stays optional there. With two or more, every
registration names its tenant or the gateway refuses to start — checked on the
documents at startup, before async key discovery, and again in
`IssuerRegistry.__init__` so that no construction path can miss it. Half
labelled is refused too: an unlabelled registration alongside a labelled one
still collides with every other unlabelled principal.

**2. Within one tenant: the issuer joins the identity key.** ADR 0051
deliberately permits two identity providers to share a tenant label — a staff
directory and a CI system, say. Inside that tenant the label cannot separate
`alice@staff` from `alice@ci`, and they are two people. The issuer now spans the
result-cache key (`acp-result-v3`) and the budget account
(`[tenant, subject, issuer]`).

The policy engine is deliberately *not* changed. Per-tenant policy files already
give each tenant its own rulebook, and making `subjects:` issuer-qualified would
change the spelling of every rule in every deployment to close a collision the
mandatory label already closes at the tenant boundary. Two directories inside
one tenant sharing a policy is the intended reading of ADR 0051.

## Alternatives considered

**Make the identity key `(issuer, subject)` everywhere and leave labels
optional.** Closes the leak without a startup failure, and leaves the
*deployment* wrong in a way nobody sees: two organisations sharing one
untenanted gateway would still share one policy file, which is the part an
operator most needs to be told about. A refusal at startup is a worse experience
and a better outcome.

**Default the tenant label to the issuer string when it is absent.** Silently
correct, silently surprising: the label appears in budget accounts, audit
records and *policy filenames*, so a generated one produces a file the operator
never created and cannot find. Labels are short slugs because humans type them.

**Warn instead of refusing.** A warning at startup is a line in a log that a
container platform discards. This is the class of misconfiguration where the
system works perfectly until the day it matters.

## Consequences

Breaking for any deployment running more than one issuer without labels — which
is precisely the deployment that has the hole. The error names every unlabelled
issuer and says what to do.

Result-cache entries are invalidated by the key-version bump, which is a cold
cache after deploy and nothing else. Budget accounts change shape, so in-flight
rate-limit and quota state resets on restart — already true of in-memory
budgets (ADR 0044).

The example configuration now shows labels, so the thing an operator copies is
the thing that is safe.

What would make us revisit: a genuine single-tenant deployment with two issuers
that finds the mandatory label an annoyance. The answer there is to give both
registrations the *same* label, which is already supported and already tested.
