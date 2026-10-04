# ADR 0059 — An operator is a verified subject, not a shared secret

**Status:** accepted
**Date:** 2026-10-04

## Context

ADR 0049 put the approval channel on the admin listener behind
`ACP_APPROVAL_OPERATOR_TOKEN`, a shared bearer compared in constant time. That
was the right first cut: it kept the write off the agent's listener and made
the channel exist only when configured. It also left a hole the threat model
listed as asset #6 without a defence worth the name: a shared secret proves
possession of the secret, so the audit row for a decision — the one record of
a human choosing — could not say *who* chose. Every approval was by "whoever
had the token", and in a multi-tenant deployment that token answered every
tenant's calls.

The repository's own evaluation (October 2026) found the row also lacked the
acting agent and the tenant, and carried the live `request_state` token into a
file the project calls durable and widely readable. Those three were fixed
first, independently of how an operator authenticates (`fix/approval-record`).
This decision is about the authentication.

## Decision

**An operator proves who they are the way an agent does: with a JWT from an
authorization server this gateway already trusts, minted for a different
audience.**

- `ACP_APPROVAL_OPERATOR_AUDIENCE` names the audience. When set, the approval
  routes accept a bearer JWT and validate it with the request path's own
  `TokenValidator`, re-targeted at that audience (`IssuerRegistry.for_audience`):
  the same issuers, the same key caches, the same `iss`-first registration
  selection, the same tenant stamping (ADR 0051). One set of trusted
  authorization servers, not two that have to agree.
- **The audience is what separates the two channels.** A token for the
  gateway's audience is refused on `:9090`; an operator's token is refused on
  `:8080`. The settings model refuses an operator audience equal to the
  gateway's, because with one audience every agent token is an operator token.
- **The verified `sub` is the operator**, recorded in the decision's audit row
  as `detail.operator`, with `operator_issuer` and `operator_verified: true`.
- **Operators are tenant-scoped.** The tenant comes from the issuer
  registration that verified the token, never a claim; an operator decides and
  lists only calls in their tenant. A call with no tenant (a single-tenant
  gateway) is open to any verified operator.
- **The shared token stays, and says what it is.** `ACP_APPROVAL_OPERATOR_TOKEN`
  still works, for a laptop and the compose stack. A decision made with it is
  recorded as `operator: shared-token`, `operator_verified: false` — not blank,
  and not a name configuration asserted. A gateway with only the shared token
  configured logs `approval.shared_token_only` at every start, the way
  `ACP_AUTH_INSECURE_ISSUER_HOSTS` announces itself.
- **An audience with nothing to verify it is refused at load.** Setting the
  audience without `ACP_AUTH_ISSUER` or `ACP_AUTH_ISSUERS_FILE` is a
  configuration error, because an audience nothing can check is not a
  credential.

## Consequences

- The audit row answers the question it exists for. "Who approved the delete"
  now has an answer an identity provider stands behind.
- One more public setting (`ACP_APPROVAL_OPERATOR_AUDIENCE`, surface minor
  bump) and three more fields in the approval row's `detail`. Nothing existing
  is renamed or removed.
- The compose stack keeps the shared token. Making Keycloak mint operator
  tokens means a client scope and an audience mapper in the committed realm,
  which is a change to test against a running Keycloak rather than in this
  decision; until then the compose gateway logs the shared-token warning on
  every start, which is the intended pressure.
- The shared token and the JWT share one `OperatorAuthenticator`, tried in a
  fixed order (constant-time token compare first, then the validator). Two
  proofs behind one seam, rather than two code paths.

## Alternatives considered

**A configured operator *name* beside the shared token.** The cheapest fix and
the one that looks like the real one: `ACP_APPROVAL_OPERATOR_NAME=alice`
written into the row. Rejected because a config file asserting an identity is
a label, and a row that says "alice" because a file said so is worse than one
that says "shared-token", since a reader will believe it.

**A second issuer registry for operators.** Operators are often in a different
realm from agents. Rejected for now: `for_audience` re-targets the existing
registry, which is enough when operators and agents share an authorization
server, and a separate `ACP_APPROVAL_OPERATOR_ISSUERS_FILE` can be added later
without disturbing this. One set of trusted issuers is the simpler claim to
defend today.

**Mutual TLS on the admin listener.** Strong, and it authenticates the client
machine rather than the person. The row still could not name who approved.

**Removing the shared token entirely.** Honest, and it would make `make up`
require a Keycloak operator token before the demo could approve anything.
Kept as the explicitly-weak option that announces itself, rather than making
the demo harder for the sake of a line in a table.
