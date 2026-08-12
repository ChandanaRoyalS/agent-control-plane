# ADR 0045 — Replay the log, report what changes, and refuse to guess

**Status:** accepted
**Date:** 2026-08-12

## Context

A policy is only useful if people edit it, and people only edit what they can
predict. Today the answer to *if I merge this, what breaks?* is "deploy it and
find out", and the rational response to that is to never tighten anything —
which is how a deny-by-default system ends up with an `allow-everything` rule at
the top. A policy nobody dares narrow is a policy that only ever gets looser.

`acp policy explain` (task 37) answers the question for one request somebody
thinks to type. That is a spot check. It cannot tell you about the request
nobody thought of, which is the one that breaks.

The gateway now records every authorization decision it makes (task 36), so the
material for a real answer exists: replay what actually happened against the
policy being proposed, and report the difference.

**The complication is that the log deliberately does not carry argument values.**
Argument values are the user's data — a `doc_id` is as likely to be a patient
record as a public page — and writing them into a log that a dozen people and
three vendors can read would put the payload this gateway exists to control into
the least controlled place in the system. But policy rules can constrain
arguments (ADR 0031). So for some recorded calls, no analysis can say what a
proposed policy would have done.

## Decision

**Replay the recorded decisions, classify each into one of five outcomes, and
report "I cannot tell" as a first-class result rather than guessing.**

### The log is the baseline, not the old policy file

What the gateway *did* is a fact. What a policy file says it *would have done*
is a re-derivation that can be wrong: the file may have changed since, or may
never have been the one that was loaded. Diffing against the record also means
the old policy need not still exist, which is the situation somebody
investigating a surprising denial is usually in.

### Five outcomes, not two

`UNCHANGED` · `NEWLY_DENIED` · `NEWLY_ALLOWED` · `SAME_VERDICT_NEW_RULE` ·
`INDETERMINATE`.

Counting allows and denies would hide two things worth seeing. `NEWLY_ALLOWED`
is separated from `NEWLY_DENIED` because they are different reviews: one is an
outage, the other is a security change, and a diff that reports "12 decisions
changed" makes a reviewer read all twelve to find out which. `SAME_VERDICT_
NEW_RULE` is reported because a rule that now shadows the one that used to
decide a call is not a functional change *today* — the verdicts agree — and the
next edit to either rule is where they stop agreeing.

### The three-state walk

The evaluator's walk with one extra state. In policy order, each rule is:

- **Cannot apply** — identity or tool does not match, *or* it constrains an
  argument the call never sent. The second is certainty, not an assumption: a
  missing argument is not a match (ADR 0031).
- **Definitely applies** — matches, constrains no arguments. It decides; nothing
  after it is reachable (first match wins, ADR 0026). Stop.
- **Might apply** — matches, and constrains only arguments the call did send.
  Record it as one possibility and keep walking, because the other possibility
  is that it did not fire and a later rule decided.

Falling off the end is the deny default (ADR 0025), appended as a possibility.
One possibility means the answer is settled; more than one means it depends on
values nobody recorded.

### Uncertainty is settled by the verdicts, not by the count

Three rules that could each decide a call but all deny it leave nothing
uncertain about whether the caller gets in — only about which rule stopped them,
and a policy edit is reviewed on the first question. Reporting that as
indeterminate would bury the real changes under noise nobody can act on.

### Argument *names* are logged, values never

This is what keeps the indeterminate set small enough to be useful. A rule
constraining `doc_id` cannot have fired on a call that sent no `doc_id`, so the
names alone convert many "cannot tell" answers into definite ones — a real gain
bought with a field that records nothing sensitive. Names come from a tool's
schema, not from the user.

The distinction between "no arguments were sent" (`frozenset()`) and "I do not
know which arguments were sent" (`None`, for records predating the field) is
kept rather than collapsed, because the first rules rules out and the second
cannot.

### Indeterminate counts as "not proven safe"

`acp policy simulate` exits non-zero when anything is `NEWLY_DENIED`,
`NEWLY_ALLOWED`, or `INDETERMINATE`, so it can gate a policy pull request.
Unproven is not the same as unchanged, and a gate that treats "I could not tell"
as "fine" passes the one case somebody needed to look at. It exits `1` — the
same code `explain` uses for a denial — and not `USAGE_ERROR`, so a red CI job
distinguishes "this would deny 40 calls that work today" from "you typed the
filename wrong".

### An empty log says so

Reporting "no changes" for a log containing no decisions would be a
reassuring way to describe having measured nothing. It says how many lines it
read, how many were other events, and how many it could not parse.

## What is verified, and how

The report is worth nothing unless the simulator agrees with the evaluator, so
that is asserted by exhaustive enumeration rather than by argument — every
policy of up to two rules over a two-tool, one-argument world, against every
argument mapping a caller could have sent (4,808 checks):

- **Soundness** — whatever the call really sent, the true decision is among the
  possibilities. Everything the report says rests on this; if the real decision
  could fall outside, `UNCHANGED` would be a claim about calls never considered.
- **Completeness** — a single possibility is settled for *every* unrecorded
  value. Without it, `possible_decisions` could return one answer by forgetting
  a rule, and every `UNCHANGED` would be a coin flip that landed right.

The log reader is verified against the *real* writer: `test_record.py` drives
`enforce_call`, renders through the real `JsonFormatter`, and reads that back,
so a field renamed on either side fails there rather than in production. A
reader tested only against its own idea of the format agrees with itself.

And the privacy claim is a test, not a docstring: a call whose argument value is
`patient-90210-diagnosis` produces a record containing `doc_id` and not the
value.

## Alternatives considered

**Log argument values so the simulation is exact.** Rejected — it would make the
audit log the most sensitive store in the system and undo the reason for
redaction. The indeterminate class is the price, and it is smaller than it looks
because names rule most of it out.

**Log a hash of each argument value.** Rejected — it cannot be compared against
the literal values in a policy rule, so it buys nothing here, and a hash of a
low-entropy value (`public`, `secret`, a patient ID from a known range) is
reversible by anyone who can guess the domain. It is the appearance of privacy.

**Assume an argument-constrained rule matched (or did not).** Rejected in both
directions. Either produces a clean report and a broken deployment, which is
precisely the failure this tool exists to prevent.

**Diff two policy files directly, without traffic.** Rejected as a different and
weaker tool. It can tell you the rules changed; it cannot tell you that the
change affects 4,000 calls a day made by one agent. Real traffic is what turns
"this rule is narrower" into "this breaks the reporting agent at 09:00".

**Replay through `evaluate` with an empty argument mapping.** Rejected — the
same trap ADR 0043 documents. A rule constraining an argument cannot match an
empty mapping, so every argument-scoped rule would silently be treated as not
firing.

## Consequences

- New `acp.policy.record` (`RecordedDecision`, `Traffic`, `parse_traffic`) and
  `acp.policy.simulate` (`Outcome`, `Replay`, `Simulation`,
  `possible_decisions`, `classify`, `simulate`). Both pure; no gateway, no
  clock, no I/O.
- `enforce_call`'s record gains `argument_names` — sorted, so two records of the
  same call are byte-identical and a diff over the log shows changes rather than
  dictionary ordering.
- New `acp policy simulate --policy <file> --log <file|-> [--show N]`.
- The parser treats every line as untrusted and counts what it skips. A
  simulator that dies on line 40,000 of a rotated log has answered no question,
  and the operator's fallback — grepping by hand — is worse than the answer it
  could have given about the other 39,999.
- `matches_without_arguments` now has three callers: the evaluator, the
  pre-dispatch check, and the simulator. None has its own copy of the match,
  which is what makes the simulator's answer mean anything (ADR 0030).

## References

- ADR 0025 — deny by default is structural
- ADR 0026 — the evaluator is a pure function (first match wins)
- ADR 0030 — one evaluator, two paths (now three)
- ADR 0031 — argument-level rules (why a missing argument is not a match)
- ADR 0043 — authorize on the routing headers (the same
  unknown-arguments problem, solved conservatively in the other direction)
