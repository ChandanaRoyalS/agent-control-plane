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

## [2.0.0] - 2026-09-10

A hardening release. An external review of 1.0.0 reproduced two bypasses and a
denial-of-service path against the controls this gateway is named for. All
1,898 tests passed against all three, which is the finding behind most of the
work here: the suite was measuring the wrong things confidently.

### Security

- **The injection firewall screened one field.** An embedded resource — a
  standard MCP content type whose text reaches the model exactly as a text
  block's does — was relayed with zero characters inspected, while the same
  payload in a text block was withheld. `structuredContent`, annotations and
  any content type added by a future spec revision were open the same way.
  Every string a result carries is now screened, with base64 image payloads the
  only exclusion, matched by key rather than by the block's declared type
  ([ADR 0059](docs/decisions/0059-screen-every-string-the-result-carries.md)).
- **Argument-level policy rules compared `str()` renderings.** A
  `require_approval` rule on `dataset: production` was skipped by sending
  `["production"]` or `{"name": "production"}`; a deny on `limit: 1000` was
  skipped by sending `1000.0`. Arguments are now compared as JSON values, and a
  value a constraint cannot address is *undecidable* rather than a miss — which
  matches a restrictive rule and fails to match a permissive one, so both
  directions fail closed
  ([ADR 0060](docs/decisions/0060-an-argument-is-a-json-value-not-its-string-form.md)).
- **Tenant isolation was opt-in, and the example configuration did not opt in.**
  `config/issuers.yaml.example` registered two identity providers with no
  `tenant` labels, so both produced `tenant=None` — and policy, the result cache
  and budget accounts are all keyed on the subject without the issuer. The
  partner directory could mint `sub: cfo@corp` and inherit the corporate CFO's
  grants, cached results and budget. A tenant label is now mandatory as soon as
  a second issuer is registered, and the issuer joins the result-cache key and
  the budget account so that two directories inside one tenant cannot collide
  either ([ADR 0061](docs/decisions/0061-a-tenant-label-is-mandatory-once-there-are-two-issuers.md)).
- **An approval did not record who gave it.** The channel was one shared bearer
  token, so the chain said somebody holding it said yes — and where several
  people hold it, the free-text reason was the only thing distinguishing them.
  Credentials now identify a named operator and the name goes in the record.
  The row also carried `request_state`: the live, still-spendable approval
  token, in clear, under a key the redactor does not match. It is gone; the
  fingerprint identifies the call and grants nothing. And the decision was
  committed *before* it was recorded, so a failing sink left a live approval
  with no record of it — the write is now ahead of the decision, and a failed
  write returns 503 with the call still held
  ([ADR 0062](docs/decisions/0062-an-approval-names-the-person-who-gave-it.md)).
- **Two processes could corrupt the audit chain silently.** ADR 0050 said "one
  process, one file" and nothing enforced it: both recovered the same head and
  interleaved entries from it, so every entry after the collision had a `prev`
  that did not match the line above — corrupt from that moment, reported as
  tampering by `acp audit verify`, with nothing failing at write time. The sink
  now takes an advisory exclusive lock and a second writer is refused at
  startup.
- **Approval eviction crossed tenants.** The in-memory store dropped the
  globally-oldest record regardless of tenant or state, so 256 calls from any
  gated principal pushed every other tenant's pending approvals out. Eviction is
  now per tenant, and decided or consumed records are swept before a live one is
  dropped.
- **The rate-limiter and quota maps grew without bound**, one entry per
  principal, created even by the read-only `retry_after` and `remaining`. Both
  are now bounded at 10,000 principals, least-recently-used; eviction refunds
  whoever held the entry.
- **The screening character budget was per content block**, so a result with
  eight blocks bought eight times the allowance and the cost of inspecting a
  result was a number the upstream chose. It is now per result (ADR 0059).

- **A hostile result could stall the request loop.** Eight content blocks of
  zero-width characters produced 262,140 `Finding` objects — 35 seconds and
  384MB, measured, on the event loop, from a size the upstream chose. Three
  bounds: the character budget is per result (above), each detector reports at
  most 64 findings for one result, and screening runs in a worker thread under
  a deadline that refuses rather than serves. The same input now screens in
  118ms and 0.5MB. Capping costs enforcement nothing — one HIGH finding from an
  enforceable detector is what withholds a result, and the sixty-fifth does not
  withhold it further.

- **The injection corpus was written by the author of the detectors, one day
  after them**, and all 43 attacks were synthetic — so the measured recall was
  partly a measurement of one person's memory of their own regexes. An external
  review wrote fifteen evasions and thirteen worked, including `Ignore *the*
  previous instructions` (one article), `<system role="admin">`, chat-template
  turn markers, `Don't` as a contraction, Hangul fillers, the Unicode TAG block,
  base64 with one character in front, and base64 wrapped at 76 columns as
  encoders emit it. The patterns are broadened, the eight surviving evasions are
  in the corpus under a new `source: external_review`, and the benign
  false-positive rate is **unchanged at 19.8% with 0 of 106 still withheld**
  ([ADR 0064](docs/decisions/0064-the-corpus-could-not-see-what-it-was-not-shown.md)).
- **The model classifier could not report the two families it exists for.**
  ADR 0042 adds it to reach `plain_assertion` and `delayed_multi_step`; its
  prompt asks the model to name them; `Family` did not define them, so every
  such finding was dropped. Two tests asserted that behaviour. Both families are
  now in the enum, and a test requires the corpus and detector taxonomies to
  agree.
- **The held-out split was a list of ids that bound nothing**, and the routine
  test suite scored it on every run — a set measured on every commit is
  development data with a ceremony attached. Each id now carries a sha256 over
  its payload *and* its expectation, verified on load; the suite scores the
  development split only, and `evaluate.py --unseal` scores the sealed one.
- **`0 of 106 benign documents withheld` was printed as `[uninformative]`.**
  True of the percentile bootstrap, which collapses on a unanimous sample, and
  false of the observation. Those rows now get an exact Clopper-Pearson bound:
  the headline becomes `[≤2.8%]`, and — pointing the other way — 5-of-5
  exfiltration recall becomes `[≥54.9%]` rather than a bare 100%.

- **The firewall now screens this repository's own documentation about it.**
  Five excerpts from ADRs 0059-0064 joined the benign corpus, including the one
  listing thirteen working evasions verbatim in a table. **0 of 111 withheld**
  (exact upper bound 2.7%); two flag, and neither detector can withhold — which
  is ADR 0039's demotion holding against a document class that did not exist
  when it was decided. Flag rate 19.8% → 20.7%
  ([ADR 0065](docs/decisions/0065-the-hardest-benign-document-is-the-one-describing-the-attack.md)).
- **Override patterns for French, Spanish, German, Portuguese and Italian**,
  accents optional. 2.0.0 left this open because the false-positive cost across
  the i18n corpus had not been measured; it has been, and it is **zero new
  findings across all eight i18n documents**. `direct_override` recall 80% →
  90%. Japanese, Korean, Arabic and Hindi still match nothing, with a test
  asserting it so the gap stays visible.

- **One transient disk error made the audit chain report tampering on itself.**
  `append` rewinds the chain on `OSError` so the sequence number is reused, which
  is right — and a buffered writer defeats it, because CPython keeps the bytes it
  could not flush and the next successful flush emits the failed line first.
  Result: `seqs [1, 2, 2, 3]`, a `prev` matching neither, and `acp audit verify`
  reporting tampering permanently on a file nobody touched. The sink now writes
  raw and unbuffered, measures what landed by the file's own size rather than by
  what `write` returned, and refuses to write past a torn line instead of burying
  it. **The existing test passed against this bug** because it substituted a
  handle with no buffer; the helper now patches the raw descriptor, and all three
  failure tests fail against the previous implementation
  ([ADR 0066](docs/decisions/0066-a-buffer-defeats-the-rewind-that-protects-the-chain.md)).

### Changed — breaking

- **`ACP_APPROVAL_OPERATOR_TOKEN` no longer starts a gateway.** A single shared
  credential means an approval names nobody, and recording it as `shared` with a
  warning made the fix opt-in — which ADR 0061, three commits earlier, argues
  against for the same shape of problem. Configure
  `ACP_APPROVAL_OPERATORS_FILE` with one credential per person; the startup
  error carries the file format. A gateway whose policy never holds a call for a
  human needs neither.
- Operator credentials must be at least 32 characters. The shipped
  `dev-only-operator-token` was 23, on a channel that shows every argument of
  every held call. Compose now mounts `config/operators.compose.yaml`.
- Registering more than one issuer without a `tenant` label on every one of
  them is now a startup failure. One issuer stays unlabelled-by-default.
- The result-cache key version moves to `acp-result-v3` and budget accounts
  gain a third field, both to admit the issuer. Caches are cold after deploy;
  in-memory budget state resets, as it already did on any restart.
- `args:` constraints are typed. A rule may now match calls it previously
  missed (a list containing the value, a float equal to an integer) and miss
  calls it previously matched (a string spelling a number, `"true"` against a
  boolean). Every such change moves toward the rule's evident intent, but it is
  a change in meaning. No policy file shipped in this repository uses `args:`.
- `args:` gains explicit operators — `equals`, `not_equals`, `gt`, `gte`, `lt`,
  `lte`, `matches`, `present` — one family per argument. The bare-list shorthand
  is unchanged and means `equals`.
- Policy documents are validated harder at load time: two operator families in
  one constraint, an empty value list, a non-scalar constraint value or an
  invalid regular expression now fail at startup rather than behaving
  surprisingly at call time.

### Added

- **Supply-chain checks in CI**: `pip-audit` against the locked dependency set
  (not a fresh resolve — the lock is what ships), a CycloneDX SBOM uploaded as
  an artifact, and Dependabot for Python, Actions and Docker. The first run
  found five CVEs in `httpx`/`httpcore`, now upgraded.
- **Released images are signed.** `cosign sign` keylessly, over the *digest*
  rather than a tag — a tag is a mutable pointer, so signing one is a signature
  over "whatever is there now". An SBOM is attested against the same digest, and
  the release notes carry the digest and the `cosign verify` command.
- `ACP_APPROVAL_STORE_FILE` puts pending approvals in SQLite so a restart does
  not lose them. Unset keeps the in-memory store and warns at startup naming the
  consequence. Still one process: two gateways with two files cannot resolve
  each other's tokens, which is a different cut and stays in the threat model
  ([ADR 0063](docs/decisions/0063-durability-and-the-bounds-nobody-enforced.md)).

### Documentation

- The decisions index opens with the six ADRs written after the review, and
  says why they are the useful ones: a decision made under a plan and a decision
  made after being shown you were wrong are different kinds of evidence.
- Five ADRs opened by quoting a numbered task brief. They now open with the
  problem. The remaining `Task N` references are explained in the index rather
  than left as a puzzle — the README's *How this was built* says what the plan
  was.

### Removed

- The 40 `scripts/patch_*.py` files. They were the delivery mechanism of a
  code-generating sandbox, not tooling anybody runs, and they had been committed
  and left. The README now says how this repository was built instead of leaving
  it to be inferred from build scripts.

### Fixed

- **A configuration error reproduced the environment, secrets included.**
  Pydantic renders `input_value=...` into `str(exc)`, and for a settings model
  that input is every `ACP_*` variable in clear — so one unrelated
  misconfiguration put the client secret and operator token into whatever reads
  a startup failure. `SecretStr` does not cover this: it protects the validated
  field, and this error is raised while explaining why validation did not
  finish. Errors now report the field and the reason without the input.
- `ACP_AUTH_CLIENT_SECRET` and `ACP_APPROVAL_OPERATOR_TOKEN` are `SecretStr`,
  so a `repr()` of the settings no longer carries them.
- **`token_endpoint` did not require https, while `jwks_url` did** — the wrong
  way round if you only get one. A key set is public material; the token
  endpoint receives the caller's own bearer token and this gateway's client
  secret on every exchange.
- Compose credentials moved to `.env` (see `.env.compose.example`), with the
  demo values as defaults so the stack still starts. Not because those strings
  are sensitive, but because a compose file with credentials inlined is what
  somebody copies when they build a real one.
- The version has one source. `pyproject.toml` declares
  `dynamic = ["version"]` and reads `acp.__version__`; it used to be written by
  hand in both files with a test asserting they matched, which catches the
  disagreement only after somebody makes it.
- Badges, image references and links pointed at `chandanaroyal719-bot`, which is
  not this repository. Every one of them 404'd.
- The README claimed 16 deliberate breakages and `ARCHITECTURE.md`'s table
  itemised 18. A test now fails when they disagree.
- Approvals reach the trace console for the first time. The handler used the
  synchronous `record`, which never published — and did an `fsync` on the event
  loop, the bug ADR 0053 removed from the request path and left here.
- The test suite has a 60-second per-test timeout. A hang is now a red build
  rather than a job somebody cancels twenty minutes later — and this suite
  screens attacker-shaped input, where "does not finish" is the failure mode
  being defended against.

- **The catalogue hid argument-scoped tools**, contradicting ADR 0031 and
  disagreeing with `could_ever_allow` on the pre-dispatch path. `visible_tools`
  evaluated with an empty argument mapping, so every rule carrying `args` fell
  through to the deny default. An agent that never sees a tool never names it,
  never triggers its approval, and the human is never asked. Visibility is now
  decided by the fields a listing can decide (ADR 0060).

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
- **Four mutation harnesses, 16 mutations**, all in CI: they break the
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

- Container image: `ghcr.io/ChandanaRoyalS/agent-control-plane:1.0.0`.
  Built without the mock upstreams and asserted to be, runs as uid 10001, and
  reads `config/` from a read-only mount so a compromised gateway cannot
  silence its own alarm.
- 58 architecture decision records, indexed in
  [`docs/decisions/README.md`](docs/decisions/README.md).
- 1893 tests, 94% coverage, `mypy --strict` clean.

[Unreleased]: https://github.com/ChandanaRoyalS/agent-control-plane/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ChandanaRoyalS/agent-control-plane/releases/tag/v1.0.0

