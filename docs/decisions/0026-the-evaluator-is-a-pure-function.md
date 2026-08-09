# ADR 0026 — The policy evaluator is a pure function, decided apart from enforced

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 32 loaded the rulebook. Task 33 makes a decision from it: given a policy and
the identity of a request, allow or deny, and name the rule that decided. It does
not yet *enforce* anything — refusing a denied call in the request path, and
filtering the tool catalogue so a denied tool never appears, are task 34.

Splitting decide from enforce is the same move identity made between building a
`Principal` and trusting one. The decision is pure — a function of a policy and
three strings — so it is testable in full without a running gateway, a token, or
a network. The enforcement it feeds touches the request path and the SDK, which
is exactly the code that is hardest to test and easiest to get subtly wrong, so
the less logic that lives there, the better.

## Decision

**`evaluate(policy, principal, tool) -> Decision` is a pure function**, and it is
the whole of the decision logic. `Decision` carries `allowed` and the `rule` that
decided — or `None` when nothing matched and the deny default applied.

The evaluation rules, which task 34's enforcement and every later phase assume:

- **Deny by default.** No rule matched means deny, and the decision names no
  rule. This is the absence of a rule, not a rule (ADR 0025), which is why an
  empty policy denies everything. `allowed is True` with `rule is None` is a
  state that cannot occur: an allow always names its grantor.
- **First match wins.** Rules are tried in document order; the first whose match
  fields all hold decides. The engine does not privilege deny over allow — it
  privileges position, which is what makes a narrow deny ahead of a broad allow
  mean what it reads like.
- **Membership matches; unset matches anything; set fields are ANDed.** A rule's
  `subjects`/`actors`/`tools` given as a list matches when the request value is
  in it, and left empty matches any value. All set fields must hold together.
- **A rule naming actors requires an actor.** `actors: [x]` means the actor must
  be `x`; a non-delegated request has no actor, so it satisfies "unset means any"
  but not "set means one of these", and falls through to deny. This is the one
  edge worth stating out loud, because treating a missing actor as a wildcard
  would let a rule scoped to one agent match a request made by none.

The tool is matched as its qualified name (`upstream__tool`, ADR 0003), verbatim.
Richer matching — argument predicates, globs, resource-level conditions — extends
this in a later task and does not change the four rules above.

## Alternatives considered

**Deny-overrides instead of first-match.** A model where any matching deny beats
any matching allow regardless of order. Rejected: it reads simpler but composes
worse. "Allow this narrow thing even though a broad deny covers it" becomes
inexpressible, and the order-independence it buys is not worth losing the ability
to reason about a policy top to bottom the way it is written. First-match is what
a reader already assumes a rule list means.

**Returning a bare bool.** Rejected. The rule that decided is the audit record
(task 37) and the content of an error message; discarding it here would mean
recomputing it there, or worse, not being able to. A `Decision` that names its
rule costs one field and answers the only question an incident review asks.

## Consequences

- `src/acp/policy/evaluate.py` holds `evaluate` and `Decision`, exported from the
  package. No I/O, no clock; the test suite is the whole contract.
- Nothing calls it yet. Wiring `load_policy` into startup and `evaluate` into the
  request path — refusing denied calls, filtering the catalogue — is task 34, and
  it is where the request-path and SDK coupling lives, kept out of here on
  purpose.

## References

- ADR 0025 — deny-by-default is structural (the default this evaluator applies)
- ADR 0015 — two identities, not one (why subject and actor match separately)
- ADR 0003 — namespace upstream tools (the qualified tool name matched here)
