# ADR 0060 — An argument is a JSON value, not its string form

**Status:** accepted
**Date:** 2026-09-10

## Context

ADR 0031 introduced argument-level rules with one worked example: *"support
agents may delete records, but a delete against a production dataset needs a
human."* An external review of v1.0.0 wrote that rule and then walked past it
three times.

```yaml
- name: hold-production
  effect: require_approval
  tools: [db__delete]
  args: {dataset: [production]}
- name: allow-delete
  effect: allow
  tools: [db__delete]
```

```
{"dataset": "production"}            -> held for a human        ✔
{"dataset": ["production"]}          -> allowed, nobody asked   ✘
{"dataset": {"name": "production"}}  -> allowed, nobody asked   ✘
```

And on a numeric rule, `deny ... args: {limit: ["1000"]}`:

```
{"limit": 1000}    -> denied      ✔
{"limit": 1000.0}  -> allowed     ✘
```

The implementation was `str(arguments[name]) not in allowed`. The comment above
it said matching by string form "keeps the exact-match model simple and
predictable across types", and a test named
`test_argument_values_compare_by_string_form` asserted it. All three were
describing the same mistake in agreeable language.

A tool argument is a **JSON value**. A constraint is a **YAML value**. `str()`
is not a comparison between them — it is a rendering of one of them into a form
where `1000.0`, `True` and `['prod']` are strings that happen not to equal the
string the author typed. Worse, the failures are *directional*: every one of
them makes a restrictive rule silently not fire, and restrictive rules exist to
sit in front of broad allows. A miss is not a random error; it is always the
call getting through.

`bool` deserves its own line. Python evaluates `True == 1` as true, so a matcher
that reached for `==` after fixing `str()` would have traded one type confusion
for another.

## Decision

**Compare arguments as JSON values, and make "I cannot compare these" a third
answer.** `acp.policy.arguments` returns `MATCH`, `NO_MATCH` or `UNDECIDABLE`.

`UNDECIDABLE` is the part that matters. "These are different" and "this value
has a shape my constraint cannot address" are different facts, and the old code
returned the first for both. The evaluator resolves the third state by asking
what kind of rule is asking:

> **A guard that cannot tell, fires. A grant that cannot tell, withholds
> itself.**

An undecidable constraint matches a `deny` or `require_approval` rule and fails
to match an `allow` one. Both directions fail closed, and neither depends on
anything the caller chose.

The undecidable set is kept small on purpose: a mapping where a scalar was
expected, a value nested past `MAX_VALUE_DEPTH`, a regex against a number, a
string longer than `MAX_MATCHED_CHARS`. A scalar of the *wrong type* is not
undecidable — `"production"` and `5` are different values and any author can see
it. Making that undecidable would fire every deny rule on every unrelated call,
and a control that refuses honest traffic is a control somebody switches off
(ADR 0038's opening argument, which is the reason this list is short).

Lists are addressed elementwise, because `["production"]` is how half the tools
in the world spell "the production dataset", and an author who wrote
`dataset: [production]` plainly meant to catch it. Within a list, a hit beats a
puzzle beats a miss — so appending a mapping to a list cannot dilute a match
into an abstention.

The YAML shorthand is unchanged: a bare list still means "one of these". Its
*meaning* changed, which is why this is **2.0.0** and not 1.0.1. Explicit
operators are also available — `equals`, `not_equals`, `gt`, `gte`, `lt`, `lte`,
`matches`, `present` — one family per argument, because a mapping carrying both
`equals` and `gt` has one obvious reading and two plausible ones.

**A second, quieter bug went with it.** `visible_tools` evaluated the catalogue
with an empty argument mapping. An argument constraint cannot hold for a call
with no arguments, so every argument-scoped rule fell through to the deny
default and *hid* its tool — the exact opposite of what ADR 0031 promised, and
in direct contradiction of `could_ever_allow`, which reported the same tool as
reachable. The two disagreed for four tasks and nothing noticed, because nothing
tested it. `evaluate_visibility` now answers the listing question with the
fields the listing can actually decide, via the same `matches_without_arguments`
the pre-dispatch check and the simulator use (ADR 0030).

## Alternatives considered

**Coerce the argument to the constraint's type before comparing.** `int("1000")`,
`bool("true")`. This is the same bug wearing a different hat: it invents a
value the caller did not send, and picks a direction to be wrong in. `"1000"` is
not the number 1000 and a policy that says it is has a type-confusion bug that
an attacker can steer.

**Make every un-comparable value a hard deny, regardless of effect.** Fails
closed everywhere, and refuses legitimate traffic whenever an allow rule meets
an argument shape it does not model. That is the behaviour that gets a control
switched off. Resolving by effect gets the same safety for guards without the
cost for grants.

**Make every un-comparable value a `NO_MATCH`, and tell operators to write
better rules.** What v1.0.0 did, phrased as a policy. It puts the burden on the
person least able to see the problem: the rule reads correctly, the tests they
write by hand pass, and the bypass is only visible to somebody who knows that
`str(["production"])` is a string.

**A full expression language — CEL, JSONPath, Rego.** Solves this and a great
deal nobody asked for. It also makes every policy file a program, and the
question "what can this rule match" stops being answerable by reading it. The
eight operators here cover the rules ADR 0031 set out to express; when one is
genuinely insufficient, that is an argument for a ninth operator, in a diff,
with a reason.

## Consequences

**Breaking.** An existing `args:` constraint may now match calls it used to
miss (a list containing the value; a float equal to an integer) and miss calls
it used to match (a string that spells a number; `"true"` against a boolean).
Every such change moves in the direction of the rule's evident intent, but it is
a change in meaning and it gets a major version. No shipped policy file in this
repository uses `args:`, so the migration surface is other people's files.

Rules are validated harder at load time: two operator families in one
constraint, an empty value list, a non-scalar constraint value or an invalid
regex now fail at startup rather than behaving surprisingly at call time.

The catalogue now shows argument-scoped tools, which is what ADR 0031 always
said and what makes the approval flow reachable from a client that only knows
what `tools/list` told it.

Twenty-five tests in `tests/unit/policy/test_arguments.py` cover the matcher
directly, and the property tests now draw `require_approval` and every JSON
shape — including the three that produced this ADR — against an oracle written
from this prose rather than copied from the implementation.

What would make us revisit: an argument shape that is genuinely common and
genuinely undecidable, showing up as guards firing on honest traffic. The fix
then is a new operator that can address it, not a wider definition of "match".
