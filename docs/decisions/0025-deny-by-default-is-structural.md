# ADR 0025 — Deny-by-default is structural, not a setting

**Status:** accepted
**Date:** 2026-08-09

## Context

Phase 3 is the policy engine: deciding what an authenticated caller may actually
do. Phase 2 established *who* is asking — a principal with a subject and an actor
(ADR 0015). Nothing yet decides *what* that principal may do, so every
authenticated caller can reach every tool. This is the gap Phase 3 closes, and
it is the "only tell the caller about the doors they're allowed through" idea
the whole project is built around.

Task 32 is the first half of that engine, and deliberately only the first half.
It defines and loads the **rulebook** — a validated policy document, read at
startup — but it does not evaluate anything. Turning a policy plus a request into
an allow/deny decision, and filtering the tool catalogue by it, are later tasks
(33 onward). Splitting load/validate from evaluate mirrors how identity was
built: a configuration that fails fast, and an enforcement path that is allowed
to trust it.

The one decision task 32 has to get right, because everything downstream assumes
it, is the default. When a request matches no rule, what happens?

## Decision

**The default is deny, and it is not configurable.**

There is no `default: allow` field, no `ACP_POLICY_DEFAULT` environment variable,
no boolean anywhere that flips the fallthrough behaviour. A request that matches
no rule is denied, full stop, and the only way a policy can permit anything is a
rule whose effect is `allow`, written in the file.

This is enforced in the shape of the schema rather than left to the evaluator:

- The `Policy` model has no default field to set. The deny fallthrough is the
  fixed behaviour of the engine (task 33), stated in the type so no future edit
  can turn it into a setting.
- A `Rule`'s `effect` has **no default**. A rule that matched everything and
  omitted its effect would be the most dangerous line in a policy file, so the
  schema refuses it — the omission is a validation error, not a guess.
- An empty rule set (`rules: []`) is valid and means "deny everything". A
  gateway with an empty policy starts and refuses every call; it does not fail
  to start. The safe direction for a truncated policy is locked doors, not open
  ones.
- A missing or malformed policy file is a **boot failure** that names the file,
  exactly like `load_upstreams`. This is the deliberate opposite of the
  schema-baseline file (ADR 0013), which is non-fatal when missing because a
  drift *monitor* must never be able to stop the gateway. Policy is the control
  itself, not a monitor of one, so its absence is fatal.

An explicit `deny` effect exists even though the default is already deny, because
it is not redundant: a narrow deny placed ahead of a broad allow expresses
"these agents may use the CRM, except the destructive tool" as one deny and one
allow. Without it, the same intent is an allow-list of every tool but one, which
grows a hole every time the upstream adds a tool. Rules evaluate top to bottom,
first match wins — which is what makes that ordering meaningful, and is recorded
here so task 33 implements the order the schema was designed around.

## Alternatives considered

**A `default_allow` boolean, off by default.** Rejected. A boolean that is safe
only in one position is a boolean somebody flips for a demo and forgets, and the
failure it produces is the quiet kind — every request permitted, no error, no log
line that looks wrong. The correct default should not be a value someone can
un-set; it should be the only thing the type can express.

**Deny-by-default enforced only in the evaluator (task 33).** Rejected as the
sole mechanism. Putting it solely in the evaluator means a policy file can be
written that *looks* like it allows-by-default, and the safety depends on a
reader trusting code they cannot see from the file. Baking it into the schema —
no default field, required `effect` — makes the unsafe policy impossible to write
in the first place, which is the same "remove the attack class by construction"
move as filtering the tool catalogue.

## Consequences

- `src/acp/policy/` holds the schema (`schema.py`) and loader (`loader.py`).
  `config/policy.yaml` is a committed starter policy demonstrating a narrow deny
  ahead of scoped allows.
- `GatewaySettings` gains a `policy_file` setting (defaulting to
  `config/policy.yaml`). The setting is defined now; loading it into startup is
  task 33, alongside the evaluator that gives a loaded policy something to do.
- Nothing in the running gateway changes yet. The rulebook is loaded and
  validated in tests, but no request is decided by it until task 33.
- The rule vocabulary here is deliberately the simplest that expresses real
  rules: match by subject, actor, and qualified tool name, all ANDed, list-means-
  membership, unset-means-any. Richer matching — argument predicates, globs,
  resource-level rules — is a later task and extends this rather than replacing
  it.

## References

- ADR 0013 — schema drift is a security control (the non-fatal-when-missing
  contrast: a monitor must not stop the gateway; a control's absence must)
- ADR 0015 — two identities, not one (why rules match subject and actor
  separately)
- ADR 0016 — bind every credential to its issuer (the deny-by-default posture,
  applied to issuer registration)
