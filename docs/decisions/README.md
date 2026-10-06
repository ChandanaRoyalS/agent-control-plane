# Architecture decisions

Fifty-nine decisions, each about ten minutes to read, each with the
alternatives that were rejected and why.

**Where a decision was made because something was measured, the measurement is
in it.** Where it was a judgement call, the ADR says so and names what would
change its mind. Where a later run disagreed with the decision, the ADR was
amended rather than quietly corrected — 0053 and 0054 both score predictions
that lost.

If you have ten minutes and want the ones that carry the most weight:

| | |
|---|---|
| [0025](0025-deny-by-default-is-structural.md) | deny by default, and why it is not configurable |
| [0019](0019-mint-a-credential-per-call-and-hold-none.md) | the gateway holds no upstream credential |
| [0023](0023-prove-the-invariant-and-prove-the-proof.md) | prove the invariant, then prove the test could fail |
| [0047](0047-a-baseline-not-a-threshold.md) | a baseline, not a threshold — the number that demoted two detectors |
| [0049](0049-the-operator-channel-is-not-the-agents-channel.md) | an agent cannot approve its own call because it cannot address the thing that approves calls |
| [0050](0050-an-audit-record-is-not-a-log-line.md) | a call this gateway cannot record does not happen |
| [0053](0053-durability-is-a-trade-blocking-the-loop-is-a-bug.md) | a load harness found `fsync` on the event loop before a profiler was attached |
| [0057](0057-the-demo-reports-what-happened-it-does-not-assert-it.md) | the attack demo reports rather than asserts, and the first run proved why |

---

## Protocol and shape

| | |
|---|---|
| [0001](0001-target-2026-07-28-spec-only.md) | one specification revision only; an earlier version is refused by name rather than half-supported |
| [0002](0002-use-mcp-python-sdk-v2-beta.md) | the v2 beta, pinned exactly, upgraded by reading the changelog rather than by floating a range |
| [0003](0003-namespace-upstream-tools.md) | every upstream tool is `<upstream>__<tool>`, with a truncation rule for the 64-character ceiling |
| [0004](0004-hand-roll-mock-protocol-layer.md) | the mocks are hand-rolled, because a mock built on the SDK cannot express the bugs the SDK has |
| [0005](0005-hybrid-protocol-layer.md) | hand-rolled outbound client, SDK inbound server — different jobs, different tools |
| [0008](0008-validate-requests-against-the-spec.md) | validate against the specification, not against our own mocks |

## Resilience and observability

| | |
|---|---|
| [0006](0006-layer-resilience-as-wrappers.md) | retry, breaker and cache are wrappers over one protocol, assembled in exactly one place |
| [0007](0007-structured-logging-on-the-standard-library.md) | events, not sentences: the message is a stable identifier and the detail is fields |
| [0009](0009-trace-only-the-half-the-sdk-does-not.md) | instrument the outbound half only, because the SDK already traces the inbound one |
| [0010](0010-metrics-on-a-separate-listener.md) | the metrics endpoint is a reconnaissance report, so it gets its own loopback listener |
| [0011](0011-withdraw-unhealthy-upstreams.md) | an unhealthy upstream leaves the merged catalogue entirely, rather than failing at call time |
| [0012](0012-honour-cache-hints-within-limits.md) | honour an upstream's TTL hint, clamped — a hint is input, not instruction |
| [0013](0013-schema-drift-is-a-security-control.md) | a changed tool description is an attack, not an ops event |
| [0014](0014-ship-one-image-and-compose-the-rest.md) | one image without the mocks; `config/` mounted read-only so a compromised gateway cannot silence its own alarm |

## Identity, and the credential that never travels

| | |
|---|---|
| [0015](0015-two-identities-not-one.md) | who it is *for* and which agent *did it* are different questions; asymmetric algorithms only |
| [0016](0016-bind-every-credential-to-its-issuer.md) | issuer, audience and key set are one indivisible registration |
| [0017](0017-let-the-gateway-tell-clients-where-to-authenticate.md) | the one unauthenticated path is derived from the document served there, not from an allow-list |
| [0018](0018-one-issuer-string-from-every-vantage-point.md) | an issuer is an identity, not an address — and the plain-HTTP escape hatch is narrow, named and logged |
| [0019](0019-mint-a-credential-per-call-and-hold-none.md) | the inbound token reaches exactly one module, whose only destination is the issuer that minted it |
| [0020](0020-check-the-scope-you-were-granted.md) | RFC 8707's parameter is a *request*; the control is checking what came back names one upstream |
| [0021](0021-one-backend-behind-a-seam.md) | an encrypted store turns many secrets into one key, and says so |
| [0022](0022-a-cache-key-that-cannot-be-wrong.md) | a credential cache keyed on the request — keying it on the upstream serves one caller's credential to the next and passes every functional test |
| [0023](0023-prove-the-invariant-and-prove-the-proof.md) | the no-passthrough sweep, two static alarms, and a mutation harness that breaks it on purpose |
| [0024](0024-client-id-metadata-documents.md) | keep the registered-client exchange; do not send a URL `client_id` to this server |

## Policy

| | |
|---|---|
| [0025](0025-deny-by-default-is-structural.md) | the default is deny **and it is not configurable** — no field, no variable |
| [0026](0026-the-evaluator-is-a-pure-function.md) | `evaluate(policy, principal, tool) -> Decision` is the whole of the decision logic |
| [0027](0027-enforcement-is-the-backstop.md) | enforcement allows silently or raises; the evaluator explains |
| [0028](0028-enforce-on-the-real-request-path.md) | enforce in the handler, read the real principal, fail closed |
| [0029](0029-filter-the-catalogue-by-policy.md) | a tool the caller may not call never appears — an attack class removed by construction |
| [0030](0030-one-evaluator-two-paths.md) | the simulator calls the same evaluator live enforcement calls |
| [0031](0031-argument-level-rules.md) | rules reach into arguments, with "unset means anything" kept consistent |
| [0043](0043-authorize-on-the-routing-headers.md) | refuse on `Mcp-Method` and `Mcp-Name` before a body is parsed — and prove it refuses nothing legitimate |
| [0045](0045-replay-the-log-and-report-what-changes.md) | replay recorded decisions against a proposed policy, and report "I cannot tell" as a first-class outcome |

## Budgets

| | |
|---|---|
| [0032](0032-rate-limiting-token-bucket.md) | a token bucket per principal, checked after authorization |
| [0033](0033-cost-accounting.md) | a per-tool cost table, so a summarise and a search do not cost the same |
| [0034](0034-quotas-fixed-window.md) | a fixed, clock-aligned window — a daily quota should align to a day |
| [0044](0044-what-the-rate-limiter-does-not-do.md) | four deviations from the plan, declared: an undeclared deviation is indistinguishable from an oversight |
| [0035](0035-a-result-cache-key-that-cannot-serve-the-wrong-person.md) | the one cache that sits **inside** the policy check rather than outside it |

## The injection firewall, and what it is measured to do

| | |
|---|---|
| [0036](0036-detect-before-deciding-and-count-the-false-positives.md) | detect first, decide later, and count the false positives before enforcing anything |
| [0037](0037-tell-the-model-where-the-text-came-from.md) | fence retrieved data in a boundary the document cannot forge |
| [0038](0038-refuse-loudly-and-never-quote-the-payload.md) | a refusal that quotes the payload is a better attack than the original |
| [0039](0039-the-benign-corpus-and-the-two-detectors-it-demoted.md) | 106 ordinary documents, and the two detectors that survived being allowed to withhold |
| [0040](0040-the-adversarial-corpus-and-the-attacks-nothing-catches.md) | attack families deliberately included **because nothing catches them** |
| [0041](0041-the-held-out-split.md) | a split you may score once, so tuning cannot quietly become fitting |
| [0042](0042-the-optional-model-classifier.md) | a model may raise confidence and may never be required |
| [0046](0046-the-harness-that-reports-false-positives-first.md) | the harness prints what it got wrong before what it got right |
| [0047](0047-a-baseline-not-a-threshold.md) | a baseline beats a threshold, and the interval matters more than the point estimate |
| [0060](0060-the-held-out-split-scored-once-and-what-the-model-adds.md) | held-out v1 scored once (3/7 detected, 0/7 withheld, all as recorded) and marked spent; the model classifier, measured alone, adds no held-out recall for ~1.4 s a call |
| [0061](0061-attacks-nobody-here-wrote.md) | InjecAgent imported, split by attacker instruction with half sealed as held-out v2; patterns catch 100% of the "ignore previous instructions" form, 0% of the plain form, and withhold neither |
| [0062](0062-the-model-may-name-plain-assertion.md) | `plain_assertion` is reportable by the model alone, and the prompt's families are derived from `Family`, so the classifier's one useful answer is no longer discarded |
| [0063](0063-the-control-that-stops-the-polite-injection-is-the-policy.md) | no text detector tested separates a polite injection from a polite request (DeBERTa calls 65% of clean tool output an injection); the policy blocks or holds all 27 attacks' tool calls at no cost to the tasks |
| [0064](0064-held-out-v2-scored-once.md) | held-out v2 scored once and spent: polite form 0/595, announced 595/595, nothing withheld; policies block or hold 35/35 attack chains at no cost to the tasks |
| [0065](0065-the-catalogue-is-screened-too.md) | tool descriptions are screened with the result bar and withheld in enforce mode; 0 of 1,102 external descriptions flagged, and the polite one still passes |
| [0066](0066-an-approval-is-a-fact-about-the-fleet.md) | held approvals move to Redis behind `ACP_APPROVAL_STORE_URL`, shared by every replica; `consume` is compare-and-set so an approved token is spent exactly once; in-memory stays the default |
| [0067](0067-a-limit-is-a-limit-on-the-fleet.md) | rate-limit buckets and quota tallies move to Redis behind `ACP_BUDGET_STORE_URL`, charged in one Lua step that checks both before debiting either; the budgets' keeper is named (`Budgets`) and the in-memory one stays the default |
| [0068](0068-a-restriction-is-cleared-only-by-a-value-it-can-read.md) | an argument constraint fails closed in the direction of its rule: a `deny` or `require_approval` is cleared only by a readable scalar outside the set, an `allow` is earned only by an exact one; closes the W1 bypass |
| [0069](0069-the-unexamined-tail-is-the-trigger.md) | a screening that did not read the whole document withholds it in enforce mode; the 256 KB window stays, what it means once crossed changes; closes the W3 bypass |
| [0070](0070-the-fleet-release-made-true.md) | four findings from the same review closed: an operator audience is checked against every issuer, two unlabelled issuers are refused, the audit chain has one writer by lock, and the Redis clients have timeouts and turn their failures into one typed fail-closed refusal |
| [0071](0071-the-safe-defaults.md) | a bare start refuses without an audit file unless told otherwise, the firewall defaults to report, and every start logs which controls are on and warns about the safety ones that are off |
| [0072](0072-a-real-client-reads-the-refusal.md) | the official MCP client drives the gateway in the suite; the fast-path 403 carries the handler's JSON-RPC error, a held call from a pre-2026-07-28 client is refused legibly, and the catalogue shows a tool some call could reach |
| [0073](0073-a-model-decides-the-calls.md) | a local model served by Ollama drives the demo agent over seeded trials on each path, every transcript is committed, and the README quotes the newest record |
| [0074](0074-the-classifiers-data-before-the-classifier.md) | the learned classifier's data comes first: BIPIA imported with its test split sealed, an evasion corpus of seven disguises built from it (W9), stdlib docstrings as benign training text, and splits by group with a leakage test over every set |
| [0075](0075-a-learned-classifier-measured-once.md) | a linear classifier over character n-grams, trained and thresholded on validation only and scored once on the sealed sets: 64% of BIPIA's held-out attacks at an enforce threshold (patterns: 0% withheld), 2% of clean contexts flagged, and character-level disguises defeat it |
| [0076](0076-the-learned-classifier-withholds-only-by-choice.md) | the learned classifier runs in report mode by default and withholds only when `ACP_FIREWALL_LEARNED` and `ACP_FIREWALL_MODE` are both `enforce`: it misses ADR 0039's zero-benign bar (2% of clean BIPIA), so withholding is an operator's measured choice, not a default |
| [0077](0077-a-transformer-fixed-before-it-is-trained.md) | a small transformer on the linear model's exact splits, with base model, hyperparameters, threshold rules and the bar it must clear fixed before training; one run: 92% of BIPIA's held-out attacks at 1% clean flagged (bar met), but worse than the linear model on this project's own documents, so not served |
| [0078](0078-one-key-signs-one-chain.md) | audit entries can be signed with Ed25519: the private key is a mounted secret, the public key is committed so `verify` requires signatures, and one key signs one file from its first entry, so enabling or rotating starts a new file; it stops a writer without the key, not the key holder or truncation |
| [0079](0079-a-second-source-of-attacks.md) | AgentDojo imported as data version 2 (tool results with planted goals, one goal in three sealed, its own attack template never trained on), and the rule a model trained on it must meet to replace the gateway's, fixed before training: more internal attacks caught, no more internal or BIPIA clean documents withheld |
| [0080](0080-more-attacks-did-not-move-the-ones-that-matter.md) | the model retrained with AgentDojo failed ADR 0079's rule (same 3 of 37 internal attacks, 5 internal benign withheld against 1), so the gateway's model is unchanged; scoring found the current model withholds 23% of AgentDojo's clean tool outputs |

## Approvals, audit, tenancy

| | |
|---|---|
| [0048](0048-an-approval-is-for-a-call-not-a-token.md) | an approval is granted to a call, fingerprinted, and cannot be reused for another |
| [0049](0049-the-operator-channel-is-not-the-agents-channel.md) | the agent addresses `:8080`, a person addresses `:9090`, and that placement *is* the control |
| [0050](0050-an-audit-record-is-not-a-log-line.md) | a separate sink, a separate guarantee, and exactly what the chain does and does not detect |
| [0051](0051-a-tenant-is-an-issuer-not-a-claim.md) | a tenant comes from the registration that verified the token, never from a claim |
| [0059](0059-an-operator-is-a-verified-subject-not-a-shared-secret.md) | an operator proves who they are with a JWT for its own audience, so the audit row names a verified subject rather than whoever held a shared token |

## Performance, measured

| | |
|---|---|
| [0052](0052-a-load-test-that-does-not-average-its-own-answer.md) | latency per outcome, because an average over four populations describes no request that was made |
| [0053](0053-durability-is-a-trade-blocking-the-loop-is-a-bug.md) | `fsync` on the event loop, found by a harness rather than a profiler; four predictions scored, one wrong |
| [0054](0054-an-overhead-number-is-meaningless-without-its-switch-settings.md) | the register that prints the configuration beside the number — and found a cost table nothing was charging against |
| [0055](0055-a-control-nobody-runs-is-a-control-that-does-not-exist.md) | the sixth instance of one wiring bug, and the test derived from the settings model that ends it |

## The demo

| | |
|---|---|
| [0056](0056-the-console-is-a-view-of-the-record-not-a-second-account.md) | the trace console streams the audit chain itself, because two accounts of one event is a question nobody wants at 3am |
| [0057](0057-the-demo-reports-what-happened-it-does-not-assert-it.md) | three temptations refused, and the finding that only a demo willing to be surprised could produce |

## The release

| | |
|---|---|
| [0058](0058-a-version-is-a-promise-about-a-surface.md) | a version number is a promise about a surface, so the surface is a file and a test fails when it changes |

---

## The format

[`0000-template.md`](0000-template.md). Context, Decision, Consequences,
Alternatives considered — and a **Status** that is `accepted` or nothing, because
an ADR nobody accepted is a draft and belongs in a branch.

A decision that turned out wrong is amended in place with the correction and the
reason, not deleted. The record of having been wrong is the useful part.
