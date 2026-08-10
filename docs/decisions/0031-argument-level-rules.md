# ADR 0031 — Argument-level rules: constrain the call, not just the tool

**Status:** accepted
**Date:** 2026-08-10

## Context

Through task 36 a rule matched a whole tool: `mock-a__read_document` was allowed
or it was not, for everyone the rule named. But "may read documents" and "may
read *this* document" are different permissions, and the interesting authorization
questions live in the arguments — read only public documents, search with a bounded
limit, write only to a named channel. Task 37 lets a rule constrain the arguments a
call carries, not only which tool it names.

The schema anticipated this from task 32: it said a richer matcher "would extend,
not replace" the membership model. This is that extension.

## Decision

**A rule gains `args`: a mapping from argument name to the values it permits, with
exact-value matching and the same "unset means anything" semantics as the other
match fields.**

```yaml
- name: public-docs-only
  effect: allow
  tools: [mock-a__read_document]
  args:
    doc_id: [public-handbook, public-faq]
```

- **Exact match, extending membership — not a condition language.** `args` maps
  each constrained argument to a list of allowed values; the rule matches only
  when the call supplies that argument and its value is one of them. This is the
  same shape as `subjects` and `tools`, one level deeper. It is deliberately not
  operators, globs, ranges, or comparisons: those are a genuinely richer matcher
  and their own task. Keeping this step to exact matching keeps the evaluator a
  handful of lines and the mental model identical to what already exists.

- **A constrained argument that is missing does not match.** As a named `actors`
  cannot match a request with no actor (`None` is in no list), a rule that
  constrains `doc_id` cannot match a call that omits `doc_id`. "Set means one of
  these" excludes absent as firmly as it excludes wrong.

- **Values compare by string form.** Policy values are YAML scalars (strings); a
  tool argument may arrive as a number or boolean over JSON-RPC. Matching by the
  string form keeps exact-match predictable across types without a type system in
  the policy — `limit: [10]` matches the integer `10`.

- **Filtering stays coarse; enforcement is where arguments are checked.**
  `tools/list` has no arguments — the call has not happened. So a rule that
  constrains arguments still makes its tool *visible* (an argument-scoped allow is
  not, by itself, a reason to hide the tool), and the argument check runs at call
  time in `enforce_call`. Visibility answers "could you ever call this"; the
  argument check answers "may you call it *this way*." This is the right split:
  hiding a tool because one argument value is forbidden would be misleading, while
  refusing the specific call is exactly the guarantee enforcement exists to give.

`evaluate` and `enforce_call` gain an `arguments` parameter defaulting to empty, so
every existing caller — and every rule without `args` — behaves exactly as before.

## Alternatives considered

**A condition language (operators, prefixes, ranges).** Deferred, not rejected —
it is a real need (`limit <= 100`, `path starts-with public/`) but a much larger
design: an expression grammar, its evaluation, its own failure modes. Shipping exact
matching first delivers most of the value and leaves the richer matcher a clean,
separate task that extends this one the way this extended task 32.

**Check arguments during filtering too.** Rejected. There are no arguments at list
time; inventing a "would any argument be allowed" test would either hide tools that
are callable with the right arguments or show tools that are never callable, both
worse than the honest coarse/fine split.

**Match values by native JSON type.** Rejected as premature — it needs the policy
to declare argument types, which is complexity this exact-match step does not need.
String-form comparison is predictable and enough; typed comparison can come with the
richer matcher if it earns its place.

## Consequences

- `Rule.args` is added; `evaluate`, `_rule_matches`, and `enforce_call` take an
  `arguments` mapping; `on_call_tool` passes `params.arguments`. `visible_tools` is
  unchanged — it evaluates with no arguments, which is correct.
- `acp policy explain` gains a repeatable `--arg KEY=VALUE` flag, so the simulator
  can answer argument-level questions before deploy, the same evaluator as the live
  path (ADR 0030).
- Phase 3's policy model is now fine-grained: identity, actor, tool, and argument.
  A condition language over arguments, and the audit log, remain as later tasks.

## References

- ADR 0026 — the evaluator is a pure function (extended here with arguments)
- ADR 0028 — enforce on the real request path (where the argument check runs)
- ADR 0029 — filter the catalogue (why filtering stays coarse)
- ADR 0030 — one evaluator, two paths (the simulator that now takes --arg)
