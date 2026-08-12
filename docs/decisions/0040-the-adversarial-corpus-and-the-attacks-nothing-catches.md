# ADR 0040 — The adversarial corpus, and the attacks it admits nothing catches

**Status:** accepted
**Date:** 2026-08-12

## Context

ADR 0039 built the benign half of the measurement and it did its job: within an
hour it demoted two detectors that had been enforcing, because 106 real
documents disagreed with a threshold that had only ever been argued. This is the
other half — the attacks — and it is easier to build dishonestly than the benign
half was.

The dishonest version is one number: a detection rate. It is the number every
firewall README quotes, and it is close to meaningless, for two reasons that
compound.

First, it is a property of the corpus. A detection rate over a mix of attacks
rises when you add attacks you catch and falls when you add attacks you do not,
so "94% detection" tells a reader how the author balanced their test set, not how
the firewall behaves. ADR 0036 already argued this and sliced findings by family
to answer it; the corpus has to be sliced the same way or the slicing was
pointless.

Second, and worse: **the most important attacks are the ones a pattern-based
firewall cannot catch at all.** A well-written paragraph that asserts something
false — "this refund has already been approved", "the on-call engineer said to
skip the check" — has nothing to match. It is the attack ADR 0037's provenance
framing exists for, and no detector will ever produce a finding on it. A corpus
that quietly omits these reports a detection rate computed over the subset of
attacks the author already knew how to find. Leaving them out makes the number
look better and mean less.

## Decision

### The corpus is sliced by family, and the taxonomy is a superset of the detectors'

`AttackFamily` has seven members. Five are spelled identically to
`acp.firewall.findings.Family` — `direct_override`, `exfiltration`,
`obfuscation`, `tool_confusion`, `boundary_escape` — so a per-family detection
rate is a direct comparison rather than a mapping somebody maintains. A test
asserts the subset relation, so a detector family with no attacks, or an attack
family a detector cannot report, fails the build.

The other two families have no detector, and that is the decision:

**`plain_assertion`.** A false claim in fluent prose, no imperative required.
Nothing is misspelled, encoded, or hidden. This is the family framing is aimed
at and the family that drags the honest detection rate down where it belongs.

**`delayed_multi_step`.** A payload that is harmless in the document it appears
in and becomes an instruction only in combination with a second retrieval or a
later turn. Screening is per-result by construction (ADR 0036), so a control
that never sees two documents together cannot reason about the pair. Included so
the gap is named rather than discovered.

### Every attack records what the firewall is expected to do — including nothing

Three expectations: `withheld`, `detected`, `undetected`. The third is the one
that makes the corpus honest. An attack marked `undetected` is a documented
statement that *this firewall does not catch this*, sitting in the same table as
the successes, where a reader can see the shape of the gap.

**The build fails when an expectation is wrong in either direction.** A
regression — an attack that was withheld and now is not — fails, obviously. But
an *improvement* fails too: an attack marked `undetected` that starts producing a
finding stops the build. That is deliberate and it is the same principle as the
benign corpus's anti-filler test. A security control that changes what it catches
without anybody noticing is exactly the thing this project spends its effort
preventing, and the fix is cheap and correct: one line of front matter and a
sentence here, which is precisely the review that should happen when a firewall
starts behaving differently.

### The scoreboard refuses to compute an aggregate

`acp.corpus.evaluate.Scoreboard` reports one row per family and exposes no
board-wide catch rate. A per-family `catch_rate` exists because within a family
it means something; the aggregate does not exist because across families it is
the misleading number this ADR opens with. This is enforced by a test that
asserts the attribute is absent — a control against somebody adding the
convenient `.overall` property that a later README would quote.

### What the current corpus measures

43 attacks, seven families, 20 uncatchable by design. Screened enforcing,
against a configured deployment:

| Family | Withheld | Detected | Undetected | Catches something |
|---|---|---|---|---|
| `direct_override` | 0 | 6 | 1 | 6/7 |
| `exfiltration` | 0 | 6 | 0 | 6/6 |
| `obfuscation` | 4 | 2 | 2 | 6/8 |
| `tool_confusion` | 0 | 4 | 1 | 4/5 |
| `boundary_escape` | 0 | 1 | 4 | 1/5 |
| `plain_assertion` | 0 | 0 | 7 | 0/7 |
| `delayed_multi_step` | 0 | 0 | 5 | 0/5 |

The shape is the point, and none of it is flattering:

**Only `obfuscation` is ever withheld.** That is ADR 0039 showing through: after
the demotions, the only detectors that may withhold are the bidirectional
override and the decoded-base64 ones, and both are obfuscation. Every other
family, at best, is detected-and-fenced.

**`direct_override` is detected, never withheld** — ADR 0036's MEDIUM cap, since
writing *about* the attack uses the same sentences. And one direct-override
attack is `undetected`: "You are now DevOps-GPT" evades the pattern because the
regex requires an article after "now". That is a real detector gap, recorded
rather than reshaped — reshaping the attack to match the detector would be
writing the exam around the answer.

**`boundary_escape` is mostly undetected**, and correctly so. The attacks try to
impersonate the provenance fence, and ADR 0037's nonce is why they cannot — an
attacker cannot write a closing marker for a delimiter drawn after they wrote the
document. So the attack produces no finding, the fence holds, and the outcome is
`undetected` for a *good* reason. The corpus cannot tell those two kinds of
`undetected` apart, which is a limitation stated below.

**`plain_assertion` and `delayed_multi_step` catch nothing, by design.** Twelve
attacks the firewall's detectors will never fire on. They are in the corpus so
that the number nobody should quote — a single detection rate — would be dragged
down by them if anybody computed it, which is why nobody can.

## What this does not do

**It does not measure recall.** "Detected" here means a finding was produced, not
that an attack was stopped. For most families stopping is not the detectors'
job — framing and the decision layer are — so a per-family catch rate is a
statement about the pattern layer alone. The end-to-end question is task 52's.

**It cannot distinguish a strong `undetected` from a weak one.** A
`boundary_escape` attack that produces no finding because the nonce defeated it,
and a `plain_assertion` that produces no finding because nothing was ever going
to match, are both `undetected`. The `why` field distinguishes them for a human;
the score does not.

**It is 43 synthetic attacks.** Real adversaries are more numerous, more
creative, and adapt to the control. None of these was written by someone trying
to beat *this* firewall specifically, which is the evaluation that would actually
matter and the one a study project cannot run.

**It shares the developing-set problem.** Like the benign corpus, this was
consulted while writing the code, so its expectations are fitted. The held-out
split is task 50, and until it exists no number here is a claim about attacks the
firewall has not already seen.

## Alternatives considered

**Report a single detection rate.** The number everyone expects and the one this
ADR is written to refuse. It measures the corpus.

**Omit the uncatchable families.** Produces a higher, cleaner, and dishonest
number. The whole reason to build the adversarial corpus after the benign one is
to keep resisting the flattering measurement, and this is the flattering
measurement.

**Reshape the one evading direct-override attack so the detector catches it.**
Tempting — it makes a row look better — and it is writing the test around the
implementation. The attack is realistic; the detector's article requirement is
the gap; recording it as `undetected` is the honest move and points at a real
improvement for later.

**Let an improvement pass silently.** A firewall that starts catching a
previously-uncaught attack is good news, so why fail the build? Because "the
control's behaviour changed and nobody decided it should" is the failure mode
this project exists to make impossible, and good-news drift is still drift. The
acknowledgement costs two lines.

**One combined corpus type carrying both benign and adversarial documents.**
Convenient, and it invites computing one family's rate from the other's
documents. `Corpus` and `AttackCorpus` are separate types answering separate
questions — false-positive rate and catch rate — precisely so the two cannot be
silently blended.

## Consequences

**The firewall's real shape is now visible and unimpressive on purpose.** Only
obfuscation is withheld; two whole families are uncatchable; a direct-override
attack walks through a gap in a regex. That is what the control actually does,
and a study project's value is in saying so rather than in a number.

**`make corpus` prints both halves**, and `make prove-refusal` gained a sixth
mutation — blinding the bidirectional-override detector — caught by the attack
corpus, because a detection *regression* has the same shape as an improvement: a
scoreboard row stops matching.

**The path to promoting a detector now has a scoreboard.** When tasks 51–52 add a
classifier and ask whether a demoted detector can withhold again *in combination*
with it, the question is answered against these families rather than argued.

**Two families are waiting for controls that do not exist.** `plain_assertion`
needs the classifier (task 51); `delayed_multi_step` needs cross-result state the
gateway does not keep. Both are named here as open, with a row in the table
rather than a silence.

## References

- ADR 0013 — an upstream's self-description is not trusted input
- ADR 0036 — detect before deciding, and make the false positives countable
- ADR 0037 — provenance framing, which is what `plain_assertion` is aimed at
- ADR 0038 — the refusal bar these attacks are scored against
- ADR 0039 — the benign corpus, and the demotions this ADR's numbers reflect
- OWASP GenAI Top Ten 2026, entry 1: prompt injection
