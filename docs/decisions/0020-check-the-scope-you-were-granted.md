# ADR 0020 — Check the scope you were granted, not the one you asked for

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 27 mints a credential per call, scoped to one upstream, using Keycloak's
`audience` parameter. Task 28's brief is RFC 8707 resource indicators: name the
target server in every token request so a token for A cannot be replayed
against B.

RFC 8707 names the target by **URI**. Keycloak names it by **client ID**. Those
are different mechanisms, and the obvious implementation — add a `resource`
parameter, write "RFC 8707 resource indicators" in the README — has a failure
mode this project has already paid for once. Task 23's brief named RFC 9207,
which turned out to defend a redirect-flow client and never reach a resource
server; implementing it literally would have been a citation with no control
behind it, and worse than none, because a reviewer believes it.

So before writing anything: measure.

## What Keycloak actually does

`scripts/probe_resource_indicator.py` sends the exchange six ways against
Keycloak 26.7 and reads the `aud` of what comes back. Run in CI, because CI has
Docker reliably:

| sent | resulting `aud` |
|---|---|
| `audience=acp-upstream-mock-a` | `[acp-upstream-mock-a]` |
| `resource=https://mock-a.internal/mcp` | `[acp-upstream-mock-b, acp-upstream-mock-a]` |
| `resource=acp-upstream-mock-a` | `[acp-upstream-mock-b, acp-upstream-mock-a]` |
| both, agreeing | `[acp-upstream-mock-a]` |
| **`audience=mock-a`, `resource=mock-b`** | **`[acp-upstream-mock-a]`** |
| neither | `[acp-upstream-mock-b, acp-upstream-mock-a]` |

**Keycloak accepts `resource` and discards it.** Sending it alone is
indistinguishable from sending nothing. RFC 8707 §2 says a server that cannot
honour the request SHOULD answer `invalid_target`; this one answers 200.

Two rows carry the weight.

**The contradiction case.** `audience=mock-a` with `resource=mock-b` returns a
token for mock-a and no error. The parameter is not merely unimplemented — it is
not read. A gateway that sent only `resource` would believe it had scoped a
credential that was never scoped.

**The empty case.** An exchange with no `audience` returns *every* audience the
requester can reach. So the failure mode of a missing scope is not a narrow
token or an error; it is a credential valid at every upstream in the estate,
handed to one of them. That is one absent config line away, and task 27's
startup check exists because of it.

## Decision

**Send `resource`.** It is the specified way to name a target, it costs nothing,
and any conformant authorization server acts on it. A gateway that only works
against the one server this project happens to run against is not a gateway.

**Do not treat sending it as the control.** The control is the check below.

**Verify the credential against the request.** After every exchange, read the
`aud` of the token that came back and require two things:

1. It names the requested target. Otherwise what arrived is for something else.
2. It names no *other* upstream this gateway brokers for.

The second is the confused-deputy condition written out. A credential that opens
two doors is not scoped to one, however it was requested, and an upstream
holding it can replay it against its neighbour as the caller.

**Audiences that are not upstreams are ignored** — `account`, the requester's own
client ID, whatever a given server adds. The check is about *this gateway's
estate*, which is why it has no false positives to tune away. A check with false
positives is a check somebody eventually disables.

## Why this is the right shape

The parameter is a request; the token is the fact. RFC 8707 makes honouring the
request a SHOULD, and the one server measured here does not — so a control built
on the request reports success when nothing happened. A control built on the
token is correct against a conformant server, a non-conformant one, a
misconfigured one, and a compromised one, because in all four cases it is
reading what was actually granted.

It also generalises past this task. Task 30 will cache exchanged credentials,
and a cache is a place where a token can be *reused* somewhere it was not minted
for. The check that a credential names exactly one upstream is the same check
that makes a cache key auditable.

## Alternatives considered

**Send only `resource`, since it is the RFC's mechanism.** Measurably wrong
here: it narrows nothing, so every upstream would receive a credential valid at
every other. The probe's contradiction row is this alternative failing silently.

**Send only `audience`, since it is what works.** Correct against Keycloak and
wrong everywhere else, and it bakes one vendor's spelling into a gateway whose
whole premise is standing between agents and *many* systems.

**Refuse `resource` entirely and write up the deviation**, as task 23 did with
RFC 9207. Not comparable: RFC 9207's parameter genuinely never reaches a
resource server, so implementing it would have been meaningless in principle.
RFC 8707's parameter is meaningful in principle and unimplemented in one product.
Sending it is correct; relying on it is not.

**Refuse an unverifiable (opaque) credential.** That would rule out every
authorization server issuing reference tokens, for a property the gateway cannot
observe either way. It warns `auth.scope_unverifiable` instead, and SECURITY.md
lists it as a known limit — the difference between "cannot check" and "checked,
found nothing wrong" is the whole point of not conflating them.

**Verify the exchanged token's signature too.** The gateway has the issuer's
keys, so it could. It would prove nothing useful: the credential arrived over
TLS from a token endpoint the gateway authenticated to moments earlier, and the
question being asked is a scope question, not a trust one. Verifying somebody
else's audience is the upstream's job.

**Keep the probe as a permanent CI step.** It always exits 0, so it can never
fail — and a step that can never fail is a step nobody reads. It stays in
`scripts/` behind `make probe-resource`, to be re-run when Keycloak is upgraded,
and this table is the record until then.

## Consequences

**`UpstreamConfig` gains `resource`.** Optional; `audience` remains what Keycloak
acts on. Both are per-upstream, because both name *that* upstream.

**A failed scope check fails the call**, as a non-recoverable
`CredentialExchangeError` — the same reasoning as ADR 0019. The alternatives are
sending a credential that opens doors nobody authorised, or dropping it and
calling the upstream unauthenticated.

**`auth.scope_too_broad` is logged at ERROR**, not WARNING. Every other identity
log in this project is INFO or WARNING. This one means an authorization server
returned something materially different from what was requested, which is either
a misconfiguration with security consequences or a server behaving unexpectedly,
and both deserve to page somebody.

**The smoke test asserts the property, not the parameter.** `neither credential
is valid at the other upstream`, checked by reading what each mock upstream
actually received. Asserting that `resource` was *sent* would have passed
against a server that discards it — which is precisely the trap this ADR exists
to document.

**This is the answer for Keycloak 26.7 on one date.** `make probe-resource`
re-measures it. A behaviour recorded once and assumed forever is how the next
version's change becomes a mystery.
