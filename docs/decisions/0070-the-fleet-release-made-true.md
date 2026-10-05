# ADR 0070 — The fleet release, made true

**Status:** accepted
**Date:** 2026-10-05

## Context

v1.3.0 was the release that let the gateway run as more than one process:
approvals in Redis (ADR 0066), budgets in Redis (ADR 0067), both "for the
fleet". An independent review of that release listed four medium findings
that a fleet would meet on its first day, each a few lines, each in a
different module, and each the kind of thing that is invisible from inside a
project because the single-process tests never ask the question. They are
closed together here because they are one failure in four places: a property
the design claims, left to configuration or to luck to deliver.

- **W4.** The settings model refused `ACP_APPROVAL_OPERATOR_AUDIENCE ==
  ACP_AUTH_AUDIENCE`, so a token for the gateway could not open the approval
  channel — on the single-issuer environment-variable path. With
  `ACP_AUTH_ISSUERS_FILE` every issuer has its own audience and nothing
  checked the operator audience against any of them. A token from such an
  issuer called tools on :8080 and approved them on :9090. ADR 0049's "an
  agent cannot approve its own call" was one configuration away from false.
- **W5.** Tenant labels on issuers are optional (ADR 0051). Two issuers
  without one both stamp `tenant=None`, and the result cache key, the budget
  account and the approval binding key on `(tenant, subject)`. Issuer A's
  `alice` was served issuer B's `alice`'s cached results and drained her
  budget. The example issuers file shipped exactly this configuration.
- **W6.** The audit sink had no lock. Two sinks on one path produced two
  chains in one file; the synchronous `record` path from eight threads
  produced over a hundred breaks. `acp audit verify` reported each,
  correctly, and nothing could repair them. The README said
  "tamper-evident"; the chain is SHA-256 over canonical JSON with no key.
- **W7.** `Redis.from_url(url)` with no arguments, twice. No socket timeout,
  so a hung Redis held every budgeted or held call indefinitely; the
  library's default pool, so the two-hundred-and-first concurrent command
  was a `MaxConnectionsError` rather than a queue; and the library's own
  exceptions reaching the request path, where the budget charge became an
  internal error and the approval read an unbounded wait.

## Decision

Four refusals at startup or at the call, each at the layer that owns the
property.

- **The operator audience is checked against every issuer** in
  `IssuerRegistry.for_audience`, which is where the derived operator registry
  is built and the only place that sees every registration's audience at
  once. A collision is a `ConfigurationError` at startup naming the issuers.
  The settings-model check stays; it answers earlier for the common case.
- **A registry with more than one unlabelled issuer is refused** in
  `IssuerRegistry.__init__`. One unlabelled issuer beside labelled ones is
  fine: `None` and a label are distinct accounts by construction (ADR 0051).
  The alternative — carrying the issuer into every key — would have changed
  the cache key version, the budget account format that the console parses,
  and the approval fingerprint, to encode a distinction the configuration
  should not have allowed in the first place. The example file now labels
  both its issuers, and a fifth mutation in the result-cache harness removes
  the refusal and must be caught.
- **The audit chain has one writer, by construction.** `FileAuditSink` takes
  an exclusive, non-blocking advisory lock (`flock`) on the chain for its
  lifetime; a second process on the same path refuses to start, naming the
  path. Non-blocking, because a process that waited for its sibling to exit
  would start the moment the sibling crashed and write a chain the sibling's
  restart could not continue. In-process, `append` holds a lock across the
  chain step and the write. Advisory, so `acp audit verify` reads without
  asking, as it should. The chain is **not** signed by this ADR, and the
  README now says "hash-chained" where it said "tamper-evident": an HMAC or a
  signature is a key-management decision — who holds the key, where it lives,
  how it rotates — and that is its own ADR or it is theatre.
- **One Redis client factory, one failure wrapper.** `acp.redis_url.client_for`
  builds every client with a 2-second connect timeout, a 1-second command
  timeout, a 1,024-connection pool and a 30-second idle health check; both
  stores use it. `acp.redis_url.unavailable` wraps every command the stores
  issue and turns the library's `RedisError` (connection, timeout, pool) and
  the `OSError` underneath it into one typed, recoverable
  `StateStoreUnavailableError` (`-32070`) whose wire message names nothing.
  The request path converts it like every other `ACPError`. **Fail closed, on
  purpose and legibly**: a call whose budget could not be charged, or whose
  approval could not be read, is refused with a code the agent can act on,
  not served unchecked and not left on a socket. The numbers are constants in
  code, not settings: a store that answers a budget charge in more than a
  second is down, not slow, and that is a fact about Redis rather than about
  any deployment.

## Alternatives considered

- **Key everything on the issuer (W5).** Correct in the limit, and the cost
  is paid by every component for a configuration that should be refused.
  Revisit if a real deployment needs two untenanted issuers to be distinct
  *and* cannot label them, which is hard to picture.
- **Make the sink lock blocking (W6).** Rejected above: it turns a crash
  into a silent handover between two writers.
- **Sign the chain now (W6).** The right next step and the wrong size for a
  fix PR. Listed, not done.
- **Fail open when the store is down (W7).** Serve the call without charging
  it, or treat an unreadable approval as pending. The first makes the budget
  disappear exactly when a flood has taken the store down; the second makes
  a Redis outage a way to hold every gated call forever without refusing it.
  Both are the reviewer's word "by accident" made deliberate in the wrong
  direction.
- **Expose the timeouts as settings (W7).** Three more variables for numbers
  nobody should need to change; the pool ceiling is the one a deployment
  might, and it is a constant with a comment saying when.

## Consequences

- **Upgrade note.** A deployment with two or more issuers and no `tenant`
  labels refuses to start until all but one are labelled; one whose operator
  audience equals any file issuer's audience refuses to start until it is
  distinct; two gateways sharing one audit file refuse the second. Each
  refusal names what to change. These were all misconfigurations the
  previous release accepted.
- A Redis outage is now visible as `-32070` refusals and
  `state_store.unavailable` log lines, bounded at about a second per call,
  rather than as a stalled gateway.
- The threat model's §6.5 says what the chain is and is not, and adds the
  shared stores to the trust base. §6.6 is unchanged.
- 20 deliberate breakages across the four harnesses. No new setting; the
  public surface is unchanged.

## References

- ADR 0049 — the two listeners, and the invariant W4 reached around
- ADR 0050 — the hash chain, and the checkpoint that anchors it
- ADR 0051 — tenancy from the registration; `None` and a label are distinct
- ADR 0066, 0067 — the two stores this makes safe to run
- `tests/unit/identity/test_issuers.py`, `tests/unit/audit/test_sink.py`,
  `tests/unit/test_redis_url.py` — one test per refusal, and the thread test
