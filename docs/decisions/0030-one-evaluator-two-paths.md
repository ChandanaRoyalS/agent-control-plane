# ADR 0030 — One evaluator, two paths: the policy simulator

**Status:** accepted
**Date:** 2026-08-09

## Context

By task 35 the policy is loaded, evaluated, enforced on `tools/call`, and used to
filter `tools/list`. What is missing is a way to ask the policy a question
*before* deploying it: given this principal and this tool, what would happen, and
which rule decides it? Reading a rule list and predicting its behaviour by eye is
exactly the error-prone step the deny-by-default and first-match rules exist to
contain — a `deny` placed after the `allow` it was meant to precede is invisible
until a real request hits it.

Task 36 adds that question as a command: `acp policy explain`.

## Decision

**One evaluator, two paths.** The simulator calls the same `evaluate(policy,
principal, tool)` that live enforcement calls. A live request reaches `evaluate`
through the gateway's `on_call_tool`; a simulated request reaches the identical
`evaluate` from the terminal. There is no second evaluator, no "simulation mode"
branch inside the real one — which is the only way to guarantee that what the
simulator predicts and what the gateway does cannot drift apart. A parallel
evaluator would be a second source of truth, and the first time the two disagreed
the simulator would be worse than nothing: confidently wrong.

`acp policy explain --policy <file> --subject <s> [--actor <a>] --tool <name>`:

- Loads the policy with the same `load_policy` the gateway uses, so a malformed
  policy fails here the same way it fails the boot.
- Builds a **synthetic** `Principal` from the flags — an identity to evaluate
  *against*, explicitly not a proven one. A real `Principal` is built only by the
  validator from verified claims (that invariant is why identity has one
  construction path); the simulator's principal carries a reserved issuer
  (`urn:acp:simulator`) and is never authenticated, never trusted, never used to
  reach an upstream. It exists only as the left-hand side of an evaluation.
- Prints the verdict (`ALLOW`/`DENY`), the subject and actor it evaluated, the
  matched rule (or that the deny default applied), and the `Decision.reason`
  already carries.
- **Never touches an upstream and never executes the request.** It is a question
  about the policy, not a call.
- Exits `0` on allow and non-zero on deny, so the command can gate a deploy: a CI
  step that runs `policy explain` for the requests that must succeed, and for the
  ones that must fail, turns "we think the policy is right" into a check.

## Alternatives considered

**A separate simulation function that mimics `evaluate`.** Rejected — this is the
one thing the design exists to prevent. The value of a simulator is that it is
the real decision; a lookalike that drifts is a liability.

**Reconstruct the decision by walking the rules in the CLI.** Rejected for the
same reason: it would be a second implementation of first-match-wins, and the
bug would live in the tool people use to check for bugs.

**Print only ALLOW/DENY.** Rejected. The matched rule and the reason are the
point — "denied" without "by which rule, or by the default" does not tell the
author whether the policy is wrong or the request is. Note this is the opposite
choice from the *wire*, where naming the rule is an oracle (ADR 0027): the
operator running `explain` against a file they already hold is not an attacker
probing a black box, so here the detail is help, not leak.

## Consequences

- `acp policy explain` lives in `cli.py` beside `probe`, `call`, `schemas`, and
  `secrets`, registered the same way. Argument-level predicates are **not** here —
  a tool is matched by qualified name only, as everywhere else; argument and
  resource conditions are task 37 and will extend `Rule`, `evaluate`, and this
  command together.
- The stale forward-references in the code and README are reconciled to the real
  roadmap: catalogue filtering is task 35 (done), the simulator is task 36 (this),
  argument-level rules are task 37.

## References

- ADR 0026 — the evaluator is a pure function (the single `evaluate` both paths use)
- ADR 0027 — enforcement is the backstop (why naming the rule is fine here but not on the wire)
- ADR 0025 — deny-by-default is structural (the behaviour the simulator lets you verify)
