# ADR 0068 — A guard matches loosely, a grant matches exactly

**Status:** accepted
**Date:** 2026-09-10

## Context

ADR 0060 fixed half of an argument-matching bypass. A second review found the
other half:

```
deny  db__delete where dataset in [production]   (with a broad allow behind it)

{'dataset': 'production'}    -> deny     ✓  ADR 0060
{'dataset': ['production']}  -> deny     ✓  ADR 0060
{'dataset': 'Production'}    -> allow    ✗
{'dataset': 'production '}   -> allow    ✗
```

ADR 0060 was about *types* — a list, a mapping, a float, a boolean. Strings
were still compared with `==`, so a deny rule remained bypassable by pressing
shift, and by a trailing space from a form field.

The obvious fix is to normalise: casefold and strip before comparing. It is
wrong, and the reason is the same asymmetry ADR 0060 already found.

**Normalising an `allow` rule grants more than the author wrote.** `allow
doc_id: [public]` that also matched `PUBLIC` would permit a document nobody
named. If the upstream treats those as different documents — and on a
case-sensitive store it does — that is an authorization bug introduced by a
convenience.

So blanket normalisation trades a bypass on deny rules for a bypass on allow
rules, and the second is worse: over-permitting is silent, over-refusing is not.

## Decision

**Normalise the string comparison only where a looser match is the safer one.**
One sentence covers it:

> A match should be easy to make when matching **denies**, and hard to make when
> matching **permits**.

Which yields, from the rule's effect and nothing else:

| constraint | effect | inner comparison |
|---|---|---|
| `equals` | `deny` / `require_approval` | loose |
| `equals` | `allow` | strict |
| `not_equals` | `deny` / `require_approval` | **strict** |
| `not_equals` | `allow` | **loose** |

`loosely()` is NFKC, then strip, then casefold — in that order, so a full-width
`Ｐroduction` becomes the ASCII an author typed before case is folded. `matches`
gains `re.IGNORECASE` under the same condition. Numbers are untouched: there is
no case to fold.

**`not_equals` inverts, and this is the part worth reading twice.** Its inner
comparison is negated before it decides anything, so `allow ... not_equals:
[production]` against a supplied `"Production"` must *not* permit the call —
which requires the inner equality to be loose, so that the negation refuses.
Under a `deny` rule the same constraint exempts a value from denial, so the
inner equality must be strict or the exemption is too easy to claim. One
expression covers both: `restrictive != negated`.

## Alternatives considered

**Normalise everywhere.** The obvious fix, and it introduces the allow-rule
bypass above. A convenience that widens a grant is not a convenience.

**Normalise nowhere; tell operators to write exact values.** What v2.0.0 did,
phrased as a policy. It puts the burden on the person least able to see the
problem: the rule reads correctly, their own tests pass, and the bypass is
visible only to somebody who thinks to try the shift key.

**An explicit `ignore_case: true` per constraint.** Honest and inert: the
authors who would set it are the ones who already thought about the attack, and
the rules that need it are the ones written by authors who did not. Worth adding
later for the narrow case of a genuinely case-sensitive *guard* — an author who
needs `deny` to fire only on exact bytes currently cannot say so, which is the
one thing this decision takes away.

**Normalise on the way in, at the gateway boundary.** Rewrites the caller's
argument, so the upstream receives something other than what was sent. A policy
engine that edits the request it is judging is a different and worse component.

## Consequences

Deny and approval rules now fire on case and padding variants, which is the
point, and they still do not fire on a genuinely different value —
`production-replica` and `staging` are unaffected. Looser is not loose.

Allow rules are strictly *narrower* than before for the same string: a policy
relying on `"Public"` matching `public` never worked as its author imagined, and
now fails closed instead of silently granting. That is a behaviour change inside
2.0.0 rather than across a release boundary, because 2.0.0 is unreleased.

An author who wants a case-sensitive guard cannot express it. Named above as the
future `ignore_case` operator; not built, because the default it would override
is the safe one and nobody has asked.

What would make us revisit: a deployment whose identifiers are legitimately
case-sensitive *and* whose guards over-fire because of it. The fix then is the
explicit operator, not a change to the default.
