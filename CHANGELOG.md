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

- AgentDojo as a second source of attacks (ADR 0079): 1,698 tool-result
  documents from its four environments, with 35 attacker goals planted in 38
  injection vectors under its five templates. One goal in three is sealed, and
  AgentDojo's own `important_instructions` template appears only there.
  `assemble(data_version=2)` adds it; version 1, what the committed model was
  trained on, stays the default. ADR 0079 also fixes, before training, the rule a
  model trained on it must meet to replace the gateway's.

- Signed audit entries (ADR 0078). `ACP_AUDIT_SIGNING_KEY_FILE` names an
  Ed25519 private key; each entry then carries `sig` and `kid`, and
  `acp audit verify --public-key` (default `config/audit-signing.pub`, when it
  exists) requires a valid signature on every entry, all from one key.
  `acp audit keygen` makes the pair. A gateway refuses to continue a file
  under a different signing state, so enabling signing or rotating the key
  starts a new audit file. Unsigned chains are unchanged.

### Changed

- CI and the release workflow use the current major version of every action
  (`actions/checkout@v7`, `astral-sh/setup-uv@v7`, `actions/upload-artifact@v7`,
  `docker/build-push-action@v7` and `login`, `setup-buildx`, `setup-qemu` at
  `@v4`). The old ones targeted Node.js 20, which GitHub has deprecated. No
  input this repository passes changed meaning.
- Each CI job keeps its own uv cache, so parallel jobs no longer race to save
  one shared key.

## [2.2.1] - 2026-10-05

The image now runs natively on arm64 (Apple silicon, Graviton), and item 2 of
the external review closes with a transformer measured against the linear
classifier ([ADR 0077](docs/decisions/0077-a-transformer-fixed-before-it-is-trained.md)).

**Patch** under ADR 0058: no setting, command, audit field or protocol
revision changed. The platforms an image is built for are not part of that
surface.

### Changed

- The release publishes one manifest list for `linux/amd64` and
  `linux/arm64`. Each platform's image is built alone and checked under its own
  platform (architecture, no mock upstreams, uid 10001, reported version)
  before anything is pushed; the published tags point at those checked images,
  which also stay available as `<version>-amd64` and `<version>-arm64`. A test
  holds the workflow to that order.

### Added

- `scripts/transformer.py` and `make train-transformer` / `make
  eval-transformer` (ADR 0077): fine-tunes DistilRoBERTa on the linear
  classifier's exact splits and scores it on the same rows. The run is fixed in
  advance in `TRANSFORMER_DESIGN`; `--unseal` refuses any other and refuses a
  second look. PyTorch is added per command, not as a dependency. Not on the
  request path.
- The transformer's record, `corpus/learned/transformer.json`: one run, scored
  once on the sealed sets as a second look. At its enforce threshold it catches
  91.6% of BIPIA's held-out attacks (linear: 64.2%) and flags 1.0% of clean
  contexts (2.0%), clearing the bar ADR 0077 set in advance. On the internal
  corpora it is worse: 2.8% of benign documents withheld (0.9%) and 2.7% of
  attacks caught (8.1%). A test now checks the record against the fixed design
  and the linear model's data.

## [2.2.0] - 2026-10-05

Item 2 of the external review: a learned classifier on the request path,
measured once on data nobody here shaped. On BIPIA's held-out split it
catches 64% of the attacks at the threshold allowed to withhold, where the
patterns withhold none; it also flags 2% of clean documents, and
character-level disguises defeat it
([ADR 0075](docs/decisions/0075-a-learned-classifier-measured-once.md)).
It runs in report mode by default and withholds only when an operator turns it
on ([ADR 0076](docs/decisions/0076-the-learned-classifier-withholds-only-by-choice.md)).

**Minor** under ADR 0058: one new setting, `ACP_FIREWALL_LEARNED`; no default
changed. Two things an operator will notice: firewall logs gain
`learned_classifier` findings, and each screened result costs about 1 ms per
thousand characters more.

### Added

- The learned classifier's data (ADR 0074): BIPIA's contexts and attack
  instructions imported from a pinned commit with its test split sealed; an
  evasion corpus of 500 documents, each sealed test attack disguised one of seven
  ways (W9 of the external review); CPython standard-library docstrings as benign
  training text; and `acp.corpus.training`, which assembles train, validation,
  report-only and sealed sets by group and fails if any two share a group or a
  text.
- A learned injection classifier (ADR 0075): logistic regression over
  character n-grams, trained by `scripts/train_classifier.py`, committed as
  weights and scored in pure Python. Scored once on the sealed sets: 64% of
  BIPIA's held-out attacks at its enforce threshold against 0% withheld by the
  patterns, with 2% of clean contexts flagged. CI refits it and fails if the
  committed weights differ.
- `ACP_FIREWALL_LEARNED` (`off`, `report`, `enforce`; default `report`) puts
  the learned classifier on the request path (ADR 0076). In `report` it logs a
  `learned_classifier` finding, MEDIUM at its report threshold and HIGH where
  `enforce` would withhold, and changes nothing a caller receives. It withholds
  only when this and `ACP_FIREWALL_MODE` are both `enforce`. Tool descriptions
  are not scored.

### Changed

- With the firewall on (the default, `report`), every tool result is now also
  scored by the learned classifier: about 1 ms per thousand characters, on a
  worker thread. `ACP_FIREWALL_LEARNED=off` restores the previous cost.

## [2.1.0] - 2026-10-05

Item 5 of the external review. The official MCP Python client now drives
the gateway in the test suite, and its first run found three defects that
2,212 tests had not ([ADR 0072](docs/decisions/0072-a-real-client-reads-the-refusal.md)).
And a local model can now be the demo's agent instead of a parser
([ADR 0073](docs/decisions/0073-a-model-decides-the-calls.md)). With
qwen2.5:7b over ten seeded trials per path, the injected runbook got the
compensation table into a created ticket in 2 trials directly and in none
through the gateway, where every ticket the model attempted was held for a
person. The read itself was allowed on both paths: the compose policy permits
it. llama3.2 never got past the first call on either path; in 17 of 20 trials
it described the attack's calls in its answer without making them.

**Minor** under ADR 0058: one new error code and one new verdict column, no
setting changed. Two behaviours a client can see did change, both toward what
the documentation already said: a tool with an argument-scoped rule now
appears in `tools/list`, and a pre-dispatch 403 now carries a JSON-RPC error
body instead of `{"error": "forbidden"}`. The status code is unchanged.

### Added

- `tests/integration/test_official_client.py`: the gateway driven by
  `mcp.client.Client` over the SDK's own streamable-HTTP transport, with
  nothing from this project's test helpers on the wire. It covers discovery,
  the catalogue, both refusal layers, re-spelled restrictions, the SDK's
  `input_required` loop, an agent that waits for an approval, a handshake-era
  client and the audit chain.
- `ApprovalUnsupportedError` (`-32041`, not recoverable).
- A model-driven demo ([ADR 0073](docs/decisions/0073-a-model-decides-the-calls.md)):
  a local model served by Ollama decides every call, directly and through the
  gateway via the official client. `make model-demo` runs one trial per path;
  `make model-demo-record` runs ten seeded trials each, commits every
  transcript under `docs/demo/model/`, and regenerates the README rows from
  it. A run in which the model never called a tool is refused. Calls a
  model writes into its prose as JSON are read and marked; a trial that
  names the payroll file without calling for it is counted as *described
  only*; and records are kept per model.
- The first two model records: llama3.2 and qwen2.5:7b, ten seeded trials per
  path each, under `docs/demo/model/`. `--rejudge WHY` recomputes recorded
  verdicts from their transcripts after a definition changes, notes the
  reason in the record and the README, and refuses to drop a recorded leak.

### Fixed

- A policy denial decided on the routing headers (ADR 0043) answered
  `403 {"error": "forbidden"}`, which the official client reported as
  `-32603 Server returned an error response`: an internal error, which agents
  retry. The 403 now carries the handler's own JSON-RPC error (`-32040`,
  `recoverable: false`, `id: null`), so both layers give a client the same
  refusal.
- A `require_approval` call from a client on the initialize handshake failed
  with `-32603 Handler returned an invalid result` after creating an approval
  nobody could resume. It is now refused with `-32041` before anything is held,
  and the chain records it as denied.
- A tool whose grant or restriction is argument-scoped was missing from
  `tools/list`, including the README's example (`deny` on one dataset in
  front of an `allow`). Calls to it were still served; agents could not find
  it. Visibility now asks the same "could any arguments permit this"
  question as the pre-dispatch check.
- The model demo's leak markers matched case-sensitively, so a held ticket
  titled "Compensation Review 2026" counted as the model stopping, not the
  gateway. Matching is now case-insensitive; the two committed records were
  re-judged from their transcripts (one gateway trial moved from *model
  stopped* to *held for approval*), and both say so.

## [2.0.0] - 2026-10-05

The safe defaults (ADR 0071), and the rest of the October review's
list: its low-severity findings (W11), the housekeeping, and the first
committed concurrent-load run. **Major** under ADR 0058 because a default
changed and a bare start that used to succeed now refuses.

**Upgrading from 1.x.** Set `ACP_AUDIT_FILE` to a path on a persistent
volume, or set `ACP_AUDIT_REQUIRED=false` to run without a record on
purpose; the gateway no longer starts with neither. Expect firewall log
lines: `ACP_FIREWALL_MODE` now defaults to `report`, which screens every
result and changes nothing a caller receives. Tool-level `deny` and
`require_approval` rules now also match re-spelled tool names.

### Added

- `make load-record` runs the load harness at 20 and 50 concurrent agents,
  commits locust's raw CSVs and a per-outcome summary under `perf/results/`,
  and regenerates the README's concurrent-load rows from the newest summary;
  a test fails when they disagree. Item 8 of the external review: the only
  concurrent figures were prose from a run nobody kept.

### Security

- **Tool-level `deny` and `require_approval` rules match re-spelled tool
  names** (ADR 0068, amended): `crm__Delete_Record` and `crm__delete_record `
  no longer fall through to an allow behind a deny on `crm__delete_record`.
  Grants still need the exact name.
- **Caller-supplied tool names are bounded in the audit chain.** A refused
  call's tool name is recorded verbatim only if it is at most 64 printable
  characters, as every real qualified name is; otherwise as its length and a
  hash prefix. Previously any authenticated caller could write arbitrary text
  of any length into the chain through a refused call.

### Fixed

- The trace console returned 500 for a non-ASCII bearer; it now uses the
  operator channel's bytes-safe comparison and returns 401.
- An unqualified tool name under an allow-anything rule raised a bare
  `ValueError` (an internal error with no audit row); it is now an
  `UnknownToolError` (`-32016`), audited as a failed call.
- A call admitted while the circuit breaker was closed and returning while it
  was half-open could release a probe slot it never held and decide recovery
  on stale evidence. Each call now carries the breaker epoch it was admitted
  in, and only the current epoch's calls count.
- The test that an allowed call reaches the upstream passed on any error
  other than a policy denial; it now asserts the upstream's result.
- `compose_smoke.py --help` prints usage instead of starting a run.

### Removed

- `Principal.expires_at`, `Principal.is_delegated` and `Principal.has_scope`,
  which nothing read. `scopes` and `delegation_chain` now reach the request
  log (`as_log_fields`); policy still does not consult scopes, and the field's
  docstring says so.

### Changed — breaking

- **The gateway refuses to start without an audit file** while
  `ACP_AUDIT_REQUIRED` is true, which is the default (ADR 0071). Set
  `ACP_AUDIT_FILE`, or set `ACP_AUDIT_REQUIRED=false` to run without a
  record on purpose; the second is logged at WARNING every start. This is
  the treatment `ACP_AUTH_REQUIRED` already gives a missing identity
  provider.
- **`ACP_FIREWALL_MODE` defaults to `report`** (was `off`). Every tool
  result is screened and findings are logged; nothing the caller receives
  changes. `enforce` stays opt-in; `off` is still accepted.

### Added

- Every start logs `gateway.controls`, the state of every control, and
  `gateway.safety_controls_off` at WARNING naming whichever of
  authentication, audit and the firewall is off.
- `.env.example` documents the audit chain, which it never mentioned, and
  its firewall section describes the current enforcement bar.

## [1.3.1] - 2026-10-05

Security fixes from an independent review of v1.3.0: two authorization
bypasses (ADRs 0068, 0069) and four configuration holes a replicated
deployment would meet (ADR 0070). **Upgrade from 1.3.0.** Nothing in the
public surface changed, so this is a patch under ADR 0058, but several
behaviours become stricter: argument-scoped `deny` and `require_approval`
rules now catch re-spelled and omitted arguments; tool results over 256 KB of
text are withheld in enforce mode; and three misconfigurations 1.3.0 accepted
now refuse to start (two unlabelled issuers, an operator audience an issuer
already mints, two gateways on one audit file). Run `acp policy simulate`
against a recorded log before upgrading a deployment with argument-scoped
restrictions.

### Changed

- The README's results are stated at the size they are (the second item of
  the 2026-10-05 external review's improvement list). The InjecAgent table
  now says what each row shows: 595/595 is one regex on one shared prefix,
  35/35 under least privilege is close to the benchmark's construction, and
  under the reads-allowed policy the read steps of a data-stealing chain
  execute. The internal numbers carry their caveats (0 of 106 benign
  withheld confirms a selection; the held-out split is seven documents).
  "Sealed" and "pre-registered" became "held out by convention", with the
  dates the git history does show. New: what the safety defaults are, that
  no model is in the loop, that the detectors match fixed phrasings, and
  what the next month of work would be. The decision-record and breakage
  counts are checked against the directory and the harnesses by a test.

### Security

- **An operator audience that an issuer in `ACP_AUTH_ISSUERS_FILE` already
  mints was accepted** (ADR 0070; W4 of the 2026-10-05 external review). The
  settings model checked the collision only against `ACP_AUTH_AUDIENCE`; a
  token from such an issuer was valid on the gateway and on the approval
  channel, so an agent could approve its own call. The registry now refuses
  the audience against every registered issuer, at startup.
- **Two issuers without a `tenant` label shared one principal namespace**
  (ADR 0070; W5). Both stamped `tenant=None`, and the result cache, the
  budget account and the approval binding key on `(tenant, subject)`, so
  issuer A's `alice` read issuer B's `alice`'s cached results. A registry
  with more than one unlabelled issuer is refused at startup; the example
  issuers file now labels both of its issuers. **A deployment with two
  unlabelled issuers must label all but one of them to upgrade.**
- **Two processes writing one audit file produced two interleaved chains**
  (ADR 0070; W6). The sink holds an exclusive advisory lock on the chain for
  its lifetime, so a second gateway on the same path refuses to start, and
  `append` is serialised in-process so the synchronous `record` path from
  several threads is one chain step at a time. The chain remains unsigned;
  the README and threat model now say so where they said "tamper-evident".
- **The Redis clients had no timeouts and the library's default pool**
  (ADR 0070; W7). A hung Redis held every budgeted or held call indefinitely,
  and the two-hundred-and-first concurrent command was an error rather than a
  queue. Both stores now build their client with a 2 s connect and 1 s
  command timeout, a 1,024-connection pool and idle health checks, and a
  store that cannot be reached refuses the call with a new typed,
  recoverable error (`-32070`) rather than an internal error or a wait.

- **Argument-level `deny` and `require_approval` rules could be bypassed by
  re-spelling or omitting the constrained argument** (ADR 0068; W1 of the
  2026-10-05 external review). `deny crm__delete where dataset=production`
  matched only the exact string: `Production`, `production `,
  `["production"]` and a call with no `dataset` at all fell through to the
  allow behind it. A restriction is now cleared only by a scalar whose folded
  form (NFKC, case, whitespace) is outside the set; missing or non-scalar
  values stay restricted. `allow` rules are unchanged. **Deployed policies
  with argument-scoped restrictions become stricter**; `acp policy simulate`
  reports the affected calls as `newly_denied` / `newly_gated`.
- **A payload placed past the 256 KB screening window was served in enforce
  mode** (ADR 0069; W3 of the same review). A screening that did not read the
  whole document is now a withholding trigger (`unexamined_tail`); report
  mode logs it as `would_refuse`. Results over 256 KB of text are refused in
  enforce mode and should be paged.

### Fixed

- Policy `args` values compare in one canonical form on both sides: a JSON
  `true` matches a policy `true` (previously compared as Python's `True` and
  never matched), and YAML numbers and booleans are accepted as values, so
  `limit: [10]` matches the integer ten as ADR 0031 said.
- The evaluation harness counts a withheld document as detected whatever
  withheld it, keeping `withheld <= detected`.

### Added

- `corpus/attack/obfuscation/payload-past-the-window.txt`: the W3 attack, as a
  regression gate; obfuscation is now 7/8 detected, 5 withheld. A seventh
  refusal mutation removes the new trigger and must be caught end to end.

## [1.3.0] - 2026-10-05

Durable state. Both stores the threat model listed as per-process — the
approval store (a correctness bug under replication) and the budgets (a
permissive limit under replication) — can now live in a Redis every replica
shares, each behind one presence-based setting, with the in-memory versions
staying the default. Tool descriptions are screened. Two new settings, so a
minor version under ADR 0058; nothing is removed or renamed.

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

[Unreleased]: https://github.com/ChandanaRoyalS/agent-control-plane/compare/v2.2.1...HEAD
[2.2.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v2.2.1
[2.2.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v2.2.0
[2.1.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v2.1.0
[2.0.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v2.0.0
[1.3.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.3.1
[1.3.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.3.0
[1.2.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.2.0
[1.1.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.1.1
[1.1.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.1.0
[1.0.1]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.1
[1.0.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.0

