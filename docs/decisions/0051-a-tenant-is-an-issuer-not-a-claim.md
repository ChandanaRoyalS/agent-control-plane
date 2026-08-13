# ADR 0051 — A tenant is an issuer registration, not a claim

**Status:** accepted
**Date:** 2026-08-13

## Context

Task 58: "isolated policy, budgets and credentials per tenant." The plan allows
shipping this as a documented design; the decision was to implement it.

The task turned out not to be a feature bolted on top. It is the repair of an
identity key that was too narrow: the gateway has trusted multiple issuers
since task 24, and everything downstream keyed on **`principal.subject`
alone** — the rate-limit bucket, the quota counter, and the result-cache key.
The moment two identity providers each have an `alice`, those are two different
people sharing one cache. Tenant A's alice can be served a result fetched for
tenant B's alice, recorded nowhere, visible to nobody — the exact failure the
cache's own module docstring names as "a data breach whose only symptom is
that everything works." It was latent only because every deployment so far ran
one issuer.

## Decision

### 1. The tenant comes from the issuer registration, never from a claim

Each entry in the issuers file may carry `tenant: <label>`. The validator
stamps the principal with the tenant of the registration that **verified** the
token — after the signature checked against that registration's keys and `iss`
matched that registration's issuer.

This is the entire trust argument, and it is inherited rather than built: a
token cannot claim its way into another tenant, because lying about `iss`
already fails signature verification (ADR 0024's mix-up defence). A `tenant`
*claim* would rest the boundary on the IdP's claim hygiene instead; here it
rests on the gateway's own configuration and cryptography. A token that
*carries* a tenant claim is ignored — asserted by
`test_a_claimed_tenant_is_ignored`, with real keys.

One IdP per tenant is the standard B2B shape. Many tenants behind one shared
IdP (the B2C shape) would need the claim; that is a different trust model and
a deliberate non-goal, recorded here so it is a decision when it arrives.

### 2. One policy file per tenant

`ACP_TENANT_POLICY_DIR` holds `<tenant>.yaml` per declared tenant. Isolation
by **file boundary** holds by construction: no rule in tenant A's file can
match tenant B's traffic, because B's evaluation never opens A's file.
Isolation by tenant *sections* in one file would hold by matcher discipline —
a code property to re-test every time the evaluator changes. The same argument
as the operator channel living on a listener the agent cannot address: prefer
the property that cannot regress.

The label is validated to a slug (`[a-z0-9][a-z0-9_-]{0,63}`) at registration
time, once, because it becomes a budget account, a cache key, an audit field
and a **filename** — one validation instead of four escaping disciplines.

### 3. An unknown tenant gets `DENY_ALL` — never the default policy

Selection is total: `None` → the default policy (the single-tenant gateway,
unchanged); a known tenant → its own file; an unknown tenant → a policy with
no rules, which the deny default (ADR 0025) decides entirely.

The default policy is the natural fallback and the one wrong answer: it is
some *other* tenant's rule set, and "an unconfigured tenant inherits whatever
the untenanted rules allow" is a cross-tenant grant written as a fallback.
Unknown tenants "cannot happen" — labels come from registrations, and every
registered tenant must have a policy at startup — which is precisely why the
case is handled: the claim rests on startup code in another module, and a
refactor there must degrade to refusing everything.

### 4. Missing configuration refuses to start, loudly

A declared tenant with no policy file, or declared tenants with no
`ACP_TENANT_POLICY_DIR`, is a **startup failure naming the tenant** — never a
silent deny-all. Runtime unknowns fail closed; configuration typos fail loud.
The difference is who finds out and when: a tenant silently denied everything
is an outage dressed as a policy, debugged by somebody three layers from the
missing file.

### 5. Isolation elsewhere is a wider key, not a module

- **Result cache:** the tenant joined the key material; `KEY_VERSION` bumped
  to `acp-result-v2`, so every pre-tenancy entry misses rather than being
  reinterpreted across a boundary that did not exist when it was written.
- **Budgets:** every charge goes to `account(tenant, subject)` — a JSON-list
  encoding, so a subject containing a separator cannot forge a boundary. Two
  tenants' alices drain two buckets. The limiter and counter are untouched;
  they key on what they are given.
- **Approvals:** the fingerprint gained the tenant (`acp-approval-v2`), and
  the binding check refuses "approval belongs to another tenant" *before* the
  fingerprint comparison would also catch it — belt over braces, in the
  direction where slipping is an escalation. The operator's view shows the
  tenant: "acme's alice wants to delete the dataset" is a different sentence
  from "alice wants to", and the person deciding is entitled to the true one.
- **Audit:** the `tenant` field, present-but-null since task 56 precisely so
  no chain would need migrating, is now populated at all six emit points.

### 6. Credentials were already isolated, and that is worth saying

The exchange goes to each registration's own `token_endpoint` (the mix-up
defence again), and the credential cache keys on a **digest of the subject
token itself** — which no two tenants can share, whatever their subjects are
called. Task 58 adds nothing here because ADR 0028's key was right. A task
that "implements credential isolation" on top of it would have been motion
without work.

## The honest cuts

**The compose demo runs one realm.** A live two-tenant demonstration needs a
second Keycloak realm and a second issuer entry; the wiring exists, the demo
does not yet. The isolation properties are asserted by tests at every layer
(policy selection, budget accounts, cache keys, approval binding, validator
stamping with real signatures) rather than demonstrated in compose.

**Budgets are isolated, not differentiated.** Every tenant draws from the same
capacity and refill numbers. Per-tenant *limits* (acme gets 100/s, globex 10/s)
are a table this design can add without another key change.

**Metrics carry no tenant label.** Prometheus label cardinality is a cost per
tenant per metric; the audit chain carries the tenant, and it is the artifact
that answers per-tenant questions.

**The operator channel is the gateway operator's, not the tenant's.** The
pending list shows every tenant's held calls (now labeled). Per-tenant
operator credentials would be a real feature for a real multi-tenant estate
and are not pretended to here.

**`acp policy explain` and `simulate` take one policy file.** To ask about a
tenant, pass that tenant's file. The commands do not resolve tenants.

**The secrets store is per-upstream, shared.** A static secret configured for
an upstream is presented for any tenant's call to it. Exchanged credentials —
the primary path — are per-principal and tenant-safe; the static fallback
predates tenancy and is now the weakest credential boundary. Named here so it
is a known limit rather than a discovery.

## Alternatives considered

**A `tenant` claim.** Rejected — decision 1. Supports the shared-IdP shape at
the cost of moving the boundary from the gateway's cryptography to the IdP's
claim discipline.

**Registration label with claim fallback.** Rejected: two code paths, two
trust stories, and the weaker one becomes load-bearing the first time it is
convenient.

**Tenant sections in one policy file.** Rejected — decision 2.

**Deny-all for a missing tenant policy file.** Rejected — decision 4. Fail
closed at runtime, fail loud at startup.

**A `Tenant` object threaded through every signature.** Rejected: the tenant
is one string riding an identity that already flows everywhere
(`principal.tenant`). The places that need more than the string (policy
selection) take it from the one field.

## Consequences

- `IssuerRegistration.tenant`, `TENANT_LABEL`, `tenant_labels()`;
  `Principal.tenant`, stamped in `TokenValidator.validate`.
- `acp.policy.tenancy`: `PolicySet`, `DENY_ALL`, `load_policy_set`;
  `ACP_TENANT_POLICY_DIR`; `build_server`/`build_app`/pre-dispatch accept a
  `Policy` or a `PolicySet` (a bare policy wraps as the default).
- `acp.budget.account`; `KEY_VERSION` → `acp-result-v2`;
  `FINGERPRINT_VERSION` → `acp-approval-v2`.
- Found and fixed while wiring: the pre-dispatch middleware's `_record`
  helper — whose docstring argues a sink failure must not turn a 403 into a
  500 — was defined and never called; the refusal path wrote to the sink
  directly. It now goes through the helper.

## References

- ADR 0015 — two identities, not one (the field this extends)
- ADR 0024 — the authorization-server mix-up defence (the trust this inherits)
- ADR 0025 — deny by default (what `DENY_ALL` is made of)
- ADR 0028 — the credential cache key (why credentials needed nothing)
- ADR 0035 — the result-cache key is the whole task (the bug tenancy closes)
- ADR 0048/0049 — approvals bind to a call (the fingerprint this widens)
- ADR 0050 — the audit record's tenant field, written before tenancy existed
