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

### Added

- `ACP_BUDGET_STORE_URL` (ADR 0067). Set it to a Redis URL and rate-limit
  buckets and quota tallies live there, one per payer for the whole fleet,
  charged in a single server-side step that checks both budgets before
  debiting either. Without it every replica enforces its own copy of every
  limit. The gateway refuses to start if the store is unreachable; empty
  keeps the in-memory budgets, which remain the default. Independent of
  `ACP_APPROVAL_STORE_URL`; both may name the same Redis.

- `ACP_APPROVAL_STORE_URL` (ADR 0066). Set it to a Redis URL and held
  approvals live there, shared by every replica: a caller told to wait by one
  gateway may retry against another, an operator may answer from a third, and
  a restart forgets nothing. The gateway refuses to start if the store is
  unreachable. Empty keeps the in-memory store, which remains the default;
  `ACP_APPROVAL_MAX_PENDING` does not apply to a shared store, whose bound is
  the record TTL. `redis` is a new runtime dependency.

- Tool descriptions are screened (ADR 0065). Every description, and every
  `description` string in a tool's input schema, passes the same detectors and
  the same bar as a tool result; in enforce mode a tool that crosses it is
  withheld from `tools/list`, in report mode it is served and logged. Flagged
  tools are chained to the audit log as `firewall.catalogue`. Measured first
  on 1,102 descriptions from InjecAgent's catalogue: zero findings.
  `make eval-descriptions` reproduces that. No new setting.

- `make overhead-record` writes each overhead measurement to
  `perf/results/overhead-<date>-<commit>.json` — percentiles, switch settings,
  commit, dirty flag and machine — and regenerates the README's overhead rows
  and the site's overhead tile from the newest file; a test fails when they
  disagree. The figures were previously copied by hand from ADR 0054.

### Changed

- The shared budget keeper refills the rate bucket on the wall clock the
  caller passes, since replicas share no monotonic clock; the in-memory
  limiter still refills on a monotonic one. A wall-clock step on one replica
  misgrants or withholds at most one burst, once (ADR 0067).
- An approved token is spent exactly once, however many retries carry it at
  the same moment: `consume` moves only an `APPROVED` record and reports
  whether this call did, and a retry that read `APPROVED` but lost that race
  is refused as "approval already used". Previously two retries on two
  replicas of a shared store could both proceed; with the in-memory store
  nothing could interleave, so nothing observable changes there.
- `approval.enabled` names the store (`memory` | `redis`) and logs
  `max_pending` as `null` when it does not apply.
- `firewall_decisions_total` carries a new `surface` label (`result` or
  `catalogue`); dashboards summing the metric should sum over it.
- The site said 16 deliberate breakages; the four mutation harnesses check 18.
- The README leads with the held-out external result for each layer, is about a
  quarter shorter, and says how the project was built and how its claims are
  checked.

## [1.2.0] - 2026-10-04

The evaluation release. The injection firewall is now measured on attacks
nobody on this project wrote — 2,108 InjecAgent documents, half sealed and
scored once — alongside two text detectors and the policy engine. The short
version: pattern screening catches the injection that announces itself and none
that does not; no text detector tested does better without flagging most tool
output; and the policy blocks or holds every attack's tool call (35/35 on
held-out v2) at no cost to the tasks. ADRs 0060–0064 record each step. No
setting, CLI flag or audit field changed; `plain_assertion` is a new value of
the firewall-finding `family` label.

### Added

- `scripts/evaluate_classifier.py` (`make eval-classifier`) scores the optional
  Ollama classifier on its own. With the classifier attached, the firewall's
  report cannot show what the model contributed — a benign document the patterns
  already flagged is flagged either way. This asks the model directly and keeps
  the outcomes the firewall throws away: an answer naming a family the firewall
  cannot report, malformed JSON, and
  timeouts are counted separately rather than as "no finding". Also reports
  per-call latency and whether a second run gives the same answer. Development
  split only; not a CI gate.

- `corpus/heldout.txt` accepts an `unsealed: <date>, <reference>` line. Once a
  held-out split has been scored, `scripts/evaluate.py` reports it as already
  unsealed on every run, and a later `--unseal` says plainly that it is no
  longer a generalisation estimate.

- An external attack corpus: 2,108 poisoned tool responses from InjecAgent
  (Findings of ACL 2024, MIT), imported verbatim at a pinned commit by
  `scripts/import_injecagent.py`, split by attacker instruction with half sealed
  as held-out v2. `scripts/evaluate_external.py` (`make eval-external`) scores
  recall against a template-only control with intervals over instructions, and
  `--check` runs in CI against a committed baseline (ADR 0061).

- `scripts/evaluate_hf_detector.py` (`make eval-hf-detector`) scores a
  purpose-built yes/no injection detector from Hugging Face on every
  development corpus, against the same template control. torch is pulled in for
  that run only (`uv run --with`), never into the project's dependencies.

- `scripts/evaluate_actions.py` (`make eval-actions`) evaluates the tool
  chains InjecAgent's attacks need against a least-privilege policy and a
  reads-allowed/writes-held policy, both built by rule, with the cost to the
  users' own task tools; `actions.json` beside the corpus carries the chains
  and the catalogue (ADR 0063).

### Changed

- Held-out v2 (35 InjecAgent instructions) was scored once and is marked spent
  (ADR 0064): pattern firewall 0/595 polite, 595/595 announced, 0 withheld;
  least-privilege policy 35/35 attack chains blocked; reads-allowed,
  writes-held policy 35/35 held; no task tool affected. The importer emits the
  `unsealed:` line so a re-import cannot re-seal it.
- Held-out split v1 was scored once and is marked spent (ADR 0060): patterns
  only, 3 of 7 attacks produced a finding, none was withheld, every outcome as
  the corpus recorded. ADR 0060 also records the classifier measured alone.

### Fixed

- The classifier's prompt offered seven families and the parser accepted five,
  so a model verdict of `plain_assertion` — the family the classifier exists
  for — was discarded. `plain_assertion` is now a reportable family (the model's
  alone) and the prompt's list is derived from `Family` (ADR 0062). Pattern-only
  numbers do not change.
- The site footer counted 58 architecture decisions after the 59th landed; the
  count is now read from `docs/decisions/` when the site is built.

## [1.1.1] - 2026-10-04

### Fixed

- **Identity.** A key set holding both EC and RSA keys plus a token naming the
  EC `kid` with `alg: RS256` made the validator raise `TypeError`, which
  escaped as a 500 with a traceback on every such unauthenticated request; it
  is a 401. Keys marked `use: enc` are no longer offered for signature
  verification. The token endpoint must be https (or an exempt host), the same
  rule the issuer and key set already had — it receives the client secret and
  the caller's token. The credential cache released a per-token lock only on
  LRU eviction, never on expiry; it releases it with the entry.
- **Budgets.** The request path debited the rate limit and then checked the
  quota, so a quota-refused call had spent its tokens on the way to being
  refused (ADR 0044 §3 said otherwise). Both budgets are now checked before
  either is debited. Per-principal state is bounded (10,000, LRU), and asking
  about a principal never charged no longer creates state for them. A cost
  table naming a tool that costs more than the rate-limit capacity or the quota
  limit — a tool nobody could ever call — is refused at startup.
- **Secrets.** The store logged its full inventory of secret names at INFO on
  every boot, and listed them in the "no such secret" error — the names the
  one-ciphertext design exists to keep out of a log. The log carries a count;
  the error names the missing secret and a count; `acp secrets list` names
  them. ADR 0021 now says Kubernetes and Docker secret mounts need an explicit
  `0400` mode, since both default to a readable file the gateway refuses.
- **The optional model classifier no longer blocks the event loop.** Its
  transport is a synchronous HTTP call with a five-second timeout and it was
  invoked from the request handler with no thread hop, so with the classifier
  enabled every tool call parked the whole gateway for the model's latency.
  `Firewall.ainspect` runs the screening on a worker thread, bounded to four
  concurrent model calls, when a classifier is attached (ADR 0042, amended).
- **An audit record that cannot be encoded no longer corrupts the chain.** The
  hash was taken with a `str()` fallback and the line written strictly, so a
  `detail` value JSON could not represent advanced the chain head and then
  failed to write — leaving a `prev` nothing on disk had, and making an
  untampered file verify as tampered. Records are now encoded strictly before
  anything is chained; one that cannot be is refused with the head unmoved.
- **The approval decision is chained before the store changes state, and
  through the writer's serialised path.** The operator channel called the
  synchronous `record` on the event loop after deciding, which bypassed the
  audit writer's serialisation (and ran the `fsync` on the loop), and on
  failure left an approval nobody could account for. It now awaits `arecord`
  first; a log that refuses leaves the request pending and answers 503.

### Changed

- The compose stack's `audit/` directory is no longer made world-writable
  (`chmod 777`); it is owned by the gateway's uid where the host can arrange
  it, with a loud fallback where it cannot.
- Remaining references to the author's internal plan numbering were removed
  from compose, Makefile, CI, config and docs comments.
- Container image: `ghcr.io/chandanaroyals/agent-control-plane:1.1.1`.

## [1.1.0] - 2026-10-04

### Added

- **Operators can authenticate with a JWT, and the audit row names them**
  (ADR 0059). `ACP_APPROVAL_OPERATOR_AUDIENCE` names an audience; an operator
  presents a token from an issuer the gateway already trusts, minted for that
  audience, verified by the same validator with the same issuer binding and
  tenant stamping as the request path. The decision's audit row records the
  verified subject (`detail.operator`, `operator_issuer`,
  `operator_verified`). An agent's token is refused on the channel; an
  operator decides and lists only within their tenant. The shared token still
  works and records itself as `shared-token`; a gateway running on it alone
  logs `approval.shared_token_only` at every start.

### Fixed

- **The approval view and the decision's audit row now carry the acting agent
  and the tenant.** The actor was always in the fingerprint, so an approval
  could never be spent by a different agent — but the person deciding was not
  shown which of the subject's agents was asking, and the audit row could not
  say either. Both identities, always (ADR 0015).
- **The `request_state` token is no longer written to the audit chain.** It is
  a live handle for up to five minutes, and the chain is durable and widely
  readable. The row keeps the fingerprint, which identifies the call and cannot
  spend the approval.
- **Approval-store eviction can no longer be aimed at somebody else.** Oldest-
  first eviction let any caller with one gated tool push a colleague's pending
  or approved request out of the store by asking `max_pending` times. Eviction
  now takes expired entries first, then finished ones, then the flooder's own
  pending requests, and only then anyone else's.
- A non-ASCII bearer on the admin listener was a 500 (`compare_digest` over
  `str`); it is a 401.

### Changed

- `ACP_APPROVAL_OPERATOR_TOKEN`, when set, must be at least 16 characters;
  the gateway refuses to start with a shorter one. Empty still means "no
  channel".
- The compose stack publishes the admin port to the host's loopback only
  (`127.0.0.1:9090:9090`), not to every interface.
- ADR 0049, the architecture page and the threat model now state exactly what
  "the agent cannot address the operator channel" rests on — a loopback bind
  that configuration can widen, behind a credential — rather than calling the
  address unreachable.
- Container image: `ghcr.io/chandanaroyals/agent-control-plane:1.1.0`.

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

[Unreleased]: https://github.com/ChandanaRoyalS/agent-control-plane/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.2.0
[1.1.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.1.1
[1.1.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.1.0
[1.0.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.1
[1.0.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.0

