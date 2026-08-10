# ADR 0033 — Cost accounting: weight a call's budget draw by the tool

**Status:** accepted
**Date:** 2026-08-10

## Context

Rate limiting (task 38) charges every call one token. But calls are not equal. A
model-backed summarisation costs real money and seconds; a plain read costs
almost nothing. A budget that cannot tell them apart is forced into a bad
compromise — set the limit low enough to contain the expensive calls and it
strangles the cheap ones; set it high enough for the cheap ones and the
expensive ones run away. Cost accounting lets the budget charge each call what it
is worth.

## Decision

**A per-tool cost table, loaded from its own config file, that weights the number
of tokens each call debits.**

- **A cost table maps qualified tool name to cost, with a default.** `cost_of`
  returns a tool's listed cost or the default (1.0) for anything unlisted. The
  limiter debits that many tokens instead of one. The `cost` parameter was
  already present in the token bucket from task 38, tested and unused — this task
  is largely wiring it to a real source.

- **Its own file, `config/costs.yaml`.** Cost is a distinct concern from
  connection (`upstreams.yaml`) and from authorization (`policy.yaml`), and the
  project keeps each concern in its own independently-loaded file. Cost is not a
  property of *how* to reach a tool, nor of *who* may call it — it is an
  operational budget knob, and it lives with the other budget machinery. Folding
  it into the upstreams schema would mean editing connection config to tune a
  budget, and muddy both.

- **Default cost 1.0, and the file is optional.** With no cost file, or a tool
  not listed, a call costs one — exactly rate limiting's behaviour. Turning cost
  accounting on with an empty table changes nothing; it only bites once you
  assign a tool a different weight. So this is a pure extension: no existing
  deployment behaves differently until it opts in.

- **Costs are non-negative; zero is a free call.** A cost of zero draws no budget
  — a legitimate choice for a cheap metadata or health tool, not an error. A
  negative cost, which would *refund* budget and let a caller mint calls by
  invoking a "negative" tool, is rejected at load time.

- **Looked up at the same point rate limiting is enforced.** The cost is resolved
  in `on_call_tool`, right where `enforce_rate_limit` runs, after authorization.
  The tool name is already in hand there; nothing new needs to be plumbed to the
  call site beyond the table itself.

## Alternatives considered

**Cost as a property in `upstreams.yaml`.** Rejected — see above. It reads as
natural ("a tool has a cost") but crosses concerns: connection config would carry
a budget field, and tuning budgets would mean touching the file that says how to
reach upstreams. Separation keeps each file's job single.

**Cost in the policy.** Rejected more firmly. Policy answers "may this call
happen"; cost answers "how much does it draw". Binding them means a change to
either forces a re-read of the other, and an allow rule starts carrying budget
semantics. Keep authorization and accounting apart.

**Dynamic cost from the response** (charge by tokens returned, bytes, latency).
Rejected for now — it is the genuinely right model for real spend, but it needs
the call to complete before charging, which means either provisional debiting and
reconciliation or charging after the fact, both materially more complex. A static
per-tool cost captures most of the value — the cheap/expensive distinction — and
leaves response-weighted cost as a later refinement the table does not preclude.

## Consequences

- New `acp.budget.cost.CostTable` (pure) and `acp.budget.loader.load_costs`
  (validating, file-named errors like the policy loader). `enforce_rate_limit`
  gains a `cost` parameter, defaulting to 1.0.
- `build_server`, `build_app`, and `gateway_from_configs` gain an optional
  `costs: CostTable`, threaded like `limiter`; `gateway_from_settings` loads it
  from a new optional `cost_file` setting. `on_call_tool` resolves the cost and
  passes it to enforcement. An example `config/costs.yaml` ships.
- Quotas and result caching remain in Phase 4. Response-weighted cost is a later
  refinement this table leaves room for.

## References

- ADR 0032 — rate limiting (the bucket whose `cost` parameter this feeds)
- docs/THREAT_MODEL.md — "Runaway spend", weighted now by what a call is worth
