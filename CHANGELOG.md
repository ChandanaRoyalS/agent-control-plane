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

### Changed — breaking

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

### Fixed

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

- Container image: `ghcr.io/chandanaroyal719-bot/agent-control-plane:1.0.0`.
  Built without the mock upstreams and asserted to be, runs as uid 10001, and
  reads `config/` from a read-only mount so a compromised gateway cannot
  silence its own alarm.
- 58 architecture decision records, indexed in
  [`docs/decisions/README.md`](docs/decisions/README.md).
- 1893 tests, 94% coverage, `mypy --strict` clean.

[Unreleased]: https://github.com/chandanaroyal719-bot/agent-control-plane/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/chandanaroyal719-bot/agent-control-plane/releases/tag/v1.0.0

