# ADR 0068 — A restriction is cleared only by a value it can read

**Status:** accepted; amends [ADR 0031](0031-argument-level-rules.md)
**Date:** 2026-10-05

## Context

ADR 0031 gave rules an `args` section with one semantics for every effect: the
rule matches when the call supplies the argument and its string form is in the
set; a missing argument is not a match, "as a named `actors` cannot match a
request with no actor". That reading is correct for an `allow`. For a `deny` it
is a hole, and an outside review of v1.3.0 walked through it.

Take the natural policy — the one the README uses to say what the policy layer
is for:

```yaml
- name: not-production
  effect: deny
  tools: [crm__delete_record]
  args: { dataset: [production] }
- name: deletes
  effect: allow
  tools: [crm__delete_record]
```

Under ADR 0031 the deny matched `{"dataset": "production"}` and nothing else.
`{"dataset": "Production"}`, `{"dataset": "production "}`,
`{"dataset": ["production"]}` and `{}` — the argument omitted, so the upstream's
default decides — all fell through to the allow. The reviewer verified each in
a clean clone. A model that has been talked into a destructive call can
trivially be talked into capitalising one argument, and this was the control the
README said stopped exactly that call.

Two smaller things came out of the same reading. JSON booleans were compared as
Python prints them (`True`), so a policy value of `true` never matched. And ADR
0031's claim that `limit: [10]` matches the integer 10 was false: the schema
typed the values as strings and refused a YAML number at load.

## Decision

**An argument constraint fails closed in the direction of its rule.**

- **On an `allow`, the constraint is the set of values that earn the grant.**
  The call must supply the argument as a scalar whose canonical form is exactly
  in the set. Missing, non-scalar, or differently spelled: not granted. This is
  ADR 0031 unchanged.
- **On a `deny` or `require_approval`, the constraint is the set of values that
  keep the restriction.** The call is cleared of it only by supplying the
  argument as a scalar whose *folded* form — NFKC-normalised, case-folded,
  trimmed — is outside the set. Missing, non-scalar, or a re-spelling of a
  restricted value: still restricted. `{}` is denied; `Production` is denied;
  `["production"]` is denied; `staging` is allowed.
- **Values compare in one canonical form on both sides.** A JSON boolean is
  `true`/`false`; a number is JSON's rendering; a string is itself. The schema
  now accepts YAML numbers and booleans in `args` and stores them in that form,
  so `limit: [10]` does what ADR 0031 said. Lists and objects are not scalars
  and are refused at load as policy values.

The two effects are read asymmetrically on purpose, and the asymmetry has one
rule behind it: **the doubtful case costs the caller.** A grant is a thing the
caller is asking to receive, so doubt withholds it. A restriction is a thing the
caller is asking to get past, so doubt keeps it. Folding is applied only to
restrictions for the same reason — folding an allow would let `PUBLIC` earn a
grant written for `public`, which widens it, while folding a deny lets
`PRODUCTION` keep a restriction written for `production`, which is the only
reading under which the restriction was ever real.

`require_approval` is a restriction. A variant that slipped past it would skip
the human, which is the whole control (ADR 0048).

## What else moved

- **The simulator** (ADR 0045) decides what a rule *could* have done from the
  argument *names* a call sent. A restriction constraining an argument the call
  did not send now *definitely fired* rather than definitely did not; a grant so
  constrained still definitely did not. Both are certainties, and the simulator
  agrees with the evaluator about both.
- **The pre-dispatch check** (ADR 0043) was already right: a deny with
  arguments "decides only the calls whose arguments match it; keep walking",
  and under this ADR that remains the correct answer to "could this tool ever
  be allowed".
- **The property oracle** in the evaluator's property tests is rewritten from
  this ADR's prose, independently of the implementation, as it was from ADR
  0026's. A new property states the fix directly: for a restriction on one
  value in front of a broad allow, no re-spelling, re-typing or omission of that
  value reaches the allow.

## Amendment — the tool name too (2026-10-05)

The review's low-severity list (W11) noted the same shape one field up: a
tool-level `deny crm__delete_record` in front of an allow-anything rule was
stepped around by `crm__Delete_Record` or a trailing space, if the upstream
reads those as the same tool. The tool name is caller input exactly as an
argument is, so restrictions now match it folded too, and grants still need
the exact name. `matches_without_arguments` carries it, so the evaluator, the
pre-dispatch check and the simulator agree by construction.

## Alternatives considered

- **Forbid `args` on deny rules.** Honest and simple; it also removes the one
  thing the policy language can say about a destructive call, which is the
  thing worth saying. The README's own example policy would stop loading.
- **Fold everything, both effects.** One rule instead of two, and a grant for
  `public` would then cover `PUBLIC`, `public ` and `ｐublic` — a silent
  widening of every argument-scoped allow in every deployed policy, in a
  change meant to narrow.
- **Treat a missing argument as a match for every effect.** Makes an
  argument-scoped allow grant calls that supply no argument at all, which is
  the opposite of what "may read *this* document" means.
- **A typed condition language** (`dataset != production`, `limit <= 100`).
  Still the right long-term shape and still a separate design (ADR 0031
  deferred it; this ADR does not pick it up). Membership with fail-closed
  reading is what the existing language can express today.

## Consequences

- Any deployed policy with an argument-scoped `deny` or `require_approval`
  **becomes stricter**: calls that omit the argument, or spell its value
  differently, are now caught by it. That is the fix; it is also a behaviour
  change a deployment should read its audit log for after upgrading. The
  simulator (`acp policy simulate`) reports exactly these calls as
  `newly_denied` or `newly_gated` against a recorded log.
- Argument-scoped `allow` rules are unchanged except that booleans and numbers
  now compare correctly, which can only make a previously-refused call succeed
  when the policy author meant it to.
- The README's claim that the policy stops the polite injection's action is
  now true for the variants of that action, not only for its canonical
  spelling.
- No new setting. The public surface is unchanged.

## References

- ADR 0026 — first match wins
- ADR 0031 — the `args` section this amends
- ADR 0045 — the simulator
- ADR 0043 — pre-dispatch authorization on the routing headers
- ADR 0048 — `require_approval` is for a call, not a token
- `tests/unit/policy/test_evaluate.py`, `test_evaluate_properties.py` — the
  variants, and the property that none of them reaches the grant
