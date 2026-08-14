# Architecture decisions

Fifty-seven decisions, each about ten minutes to read, each with the
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

## Approvals, audit, tenancy

| | |
|---|---|
| [0048](0048-an-approval-is-for-a-call-not-a-token.md) | an approval is granted to a call, fingerprinted, and cannot be reused for another |
| [0049](0049-the-operator-channel-is-not-the-agents-channel.md) | the agent addresses `:8080`, a person addresses `:9090`, and that placement *is* the control |
| [0050](0050-an-audit-record-is-not-a-log-line.md) | a separate sink, a separate guarantee, and exactly what the chain does and does not detect |
| [0051](0051-a-tenant-is-an-issuer-not-a-claim.md) | a tenant comes from the registration that verified the token, never from a claim |

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

---

## The format

[`0000-template.md`](0000-template.md). Context, Decision, Consequences,
Alternatives considered — and a **Status** that is `accepted` or nothing, because
an ADR nobody accepted is a draft and belongs in a branch.

A decision that turned out wrong is amended in place with the correction and the
reason, not deleted. The record of having been wrong is the useful part.
