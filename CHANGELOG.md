# Changelog

Written by hand, because `git log` records units of work and a release note
describes units of *change* — what a reader has to do differently. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [semantic versioning](https://semver.org/), over the surface named in
[ADR 0058](docs/decisions/0058-a-version-is-a-promise-about-a-surface.md).

**What the version number is a promise about**, in one line: the `ACP_*`
environment variables, the CLI, the audit record's shape and the MCP
specification revision. Not the Python API — nobody imports this, they run the
container. The promise is machine-readable in
[`docs/surface.json`](docs/surface.json) and a test fails when it changes
without somebody accepting the change.

## [Unreleased]

Nothing yet.

## [1.0.1] - 2026-10-04

### Fixed

- **A cancelled half-open probe no longer wedges the circuit breaker.** The
  breaker's transitions were serialised with an `anyio.Lock`; acquiring it is a
  cancellation point, so a probe whose task was cancelled mid-call (an agent
  disconnecting) raised out of the release path before the probe was counted
  as finished. The breaker then sat half-open with a phantom probe in flight
  and refused every caller — the health monitor included — with nothing that
  would ever let it out. The transitions contain no awaits and are now plain
  synchronous methods, run from a `finally`, so the release cannot be
  interrupted. A cancelled call is recorded as neutral evidence.
- **A straggler succeeding after the breaker opened no longer closes it.** Only
  a half-open probe's success closes the circuit; a call admitted before the
  trip is not a measurement of recovery, exactly as its failure was already
  not treated as new information.
- **An HTTP 4xx from an upstream is no longer treated as an outage.** A 401
  from a misconfigured credential, a 404 at the URL, a 405: each was mapped to
  `UpstreamUnavailableError`, retried `max_attempts` times and counted toward
  opening the breaker — so one bad API key withdrew a healthy upstream from
  every caller's catalogue. Those now raise `UpstreamProtocolError`: not
  recoverable, not retried, not a breaker failure. 408 and 429 still count as
  transient, as does every 5xx.
- **A JSON-RPC error object with a non-integer `code`** raised a bare
  `TypeError`/`ValueError` from the cast, outside the error taxonomy. It is now
  a malformed-response `UpstreamProtocolError`.

- **The identity smoke test no longer races the health prober.** The mock
  upstreams' `/debug/credential` recorded every request, probes included, and
  the smoke test's repeated `search` calls were answered from the result cache
  without reaching the upstream — so a probe landing mid-run blanked the record
  and four checks failed on an unrelated change. The mocks now record only
  `tools/call`, and the smoke test sends a distinct query per call.

### Changed

- Removed the author's internal task-plan numbering and one-shot patch scripts
  from the repository; corrected every URL to the repository's current home.
- Container image: `ghcr.io/chandanaroyals/agent-control-plane:1.0.1` — the
  first image published under the repository's current namespace.

## [1.0.0] - 2026-08-14

First release. The gateway is feature-complete against its plan, every
security claim in it is either tested or declared untested, and the numbers
below were measured rather than estimated.

### What it does

A policy-enforcing, injection-screening MCP gateway. One request path:

1. **Authenticate** the caller and resolve who they are acting for, stamping
   the tenant from the issuer registration that verified the token — never from
   a claim.
2. **Refuse early** on the routing headers, before a body is parsed, anything
   that tenant's policy could never permit.
3. **Mint** a credential scoped to one upstream. The caller's token reaches
   exactly one module and never travels onward, on any path.
4. **Authorize** deny-by-default down to the argument, and record the decision.
5. **Hold for a person** the calls a rule says no machine should decide alone,
   answered on a listener the agent cannot address.
6. **Filter the catalogue**, so a tool the caller may not call never appears.
7. **Meter** a per-tool weighted cost against a rate limit and a quota.
8. **Serve from cache** only what was fetched for the same principal, actor,
   tenant and arguments.
9. **Screen** every result for injected instructions, withhold what crosses a
   measured bar without ever quoting it, and fence the rest as retrieved data.
10. **Record** every decision, exchange, call, finding and approval in a
    hash-chained audit log, on a worker thread so one caller's durability is
    not every other caller's latency.

### Measured, not asserted

- **Injection screening**: 0 of 106 benign documents withheld; 19.8% flagged
  [13%, 27%]. Recall by family runs from 100% (exfiltration) to 0%
  (`delayed_multi_step`, `plain_assertion`) — the families nothing catches are
  in the corpus **because** nothing catches them.
- **Durability costs 2.14x of throughput**, and the load harness found `fsync`
  on the event loop before a profiler was attached.
- **Gateway overhead**: 6.7-7.2x a direct call on a cache miss, 3.2-3.4x on a
  hit, measured at concurrency 1 with the switch settings printed above the
  number. Millisecond figures are quoted as ranges because two runs of the same
  harness disagree about them by 40% and about the ratio by 5%.
- **Four mutation harnesses, 18 deliberate breakages**, all in CI: they break the
  no-passthrough invariant, the result cache's isolation, the firewall's
  refusal bar and the pre-dispatch check on purpose, and fail the build if the
  tests do not notice.

### What it does not do

Stated here rather than left to be discovered:

- **It does not stop prompt injection.** It measures how much it catches and
  publishes the families it misses.
- **It is not a proxy for arbitrary HTTP.** MCP `2026-07-28` only; an earlier
  revision is refused by name.
- **One identity provider per tenant.** Many tenants behind one issuer is a
  declared non-goal.
- **The audit chain does not detect tail truncation** — an external anchor
  does, and that is asserted as a passing test rather than papered over.
- **No audit log rotation.** The chain file grows without bound.
- **The result cache and the credential cache are in-process.** Two replicas do
  not share them.

### Published

- Container image: `ghcr.io/chandanaroyals/agent-control-plane:1.0.0`.
  Built without the mock upstreams and asserted to be, runs as uid 10001, and
  reads `config/` from a read-only mount so a compromised gateway cannot
  silence its own alarm.
- 58 architecture decision records, indexed in
  [`docs/decisions/README.md`](docs/decisions/README.md).
- 1,898 tests, 94% coverage, `mypy --strict` clean.

[Unreleased]: https://github.com/ChandanaRoyalS/agent-control-plane/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.1
[1.0.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.0

