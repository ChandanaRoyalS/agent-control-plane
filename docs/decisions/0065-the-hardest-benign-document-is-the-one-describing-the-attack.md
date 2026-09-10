# ADR 0065 — The hardest benign document is the one describing the attack

**Status:** accepted
**Date:** 2026-09-10

## Context

ADR 0064 closed the worst of the corpus's circularity by adding evasions an
outsider found. It left two things open and said so: the corpus is still mostly
written here, and non-English overrides match nothing.

Both were left open for a reason worth restating, because it is the same reason
in each case. Writing more attacks is easy. Writing them and *knowing what they
cost* is the work — a detector added without a false-positive number is a
detector nobody can defend, and ADR 0038's opening argument is that a control
which refuses honest traffic gets switched off, taking the useful half with it.

So the question for both was: what measurement would make the change
defensible?

## Decision

**Add the repository's own injection documentation to the benign corpus.** Five
excerpts from ADRs 0059 to 0064 — the documents written *about* these detectors,
months after them, by somebody thinking about the reader rather than about the
regex. One of them, 0064, contains a table of thirteen working evasions quoted
verbatim.

This is the hardest benign class there is and the most honest test available
without a third-party corpus. `source: repository` already existed for exactly
this reason: text "written to be read by humans rather than to be screened, so
it cannot have been shaped around a detector even accidentally." The benign
corpus was 93 synthetic to 13 repository; it is now 93 to 18, and the five
additions are the five documents most likely to trip the thing they describe.

**Result: 0 of 111 withheld.** Two of the five flag — 0064 on
`instruction_override` for its evasion table, 0061 on `disallowed_url` for two
example issuer URLs — and **neither detector can withhold anything**, because
ADR 0039 demoted both after the benign corpus caught them refusing the gateway's
own audit log. That demotion was decided against a document class that did not
then exist, and it holds against this one. The overall flag rate moved 19.8% to
20.7%.

**Add override patterns for five more languages** — French, Spanish, German,
Portuguese, Italian — with accents optional, since a document that lost them in
transit still reads as the instruction it is.

The measurement that makes this defensible: **zero new findings across all eight
i18n benign documents**, French being the direct overlap. The two that do flag,
Hindi and Persian, flag on `invisible_characters` for the zero-width non-joiner
their spelling requires, which was true before this change and is ADR 0039's
reason for capping that detector at MEDIUM.

`direct_override` recall moves 80% to 90%.

## Alternatives considered

**Import a published external corpus.** The genuinely independent option, and
still the right next step. Not taken here for two reasons that are about
diligence rather than effort: the licence of every candidate has to be read
before its text lands in this repository, and a corpus whose labels were
produced by somebody else's threshold has to be re-labelled against this
firewall's bar — "detected" and "withheld" are this project's words. Doing that
badly would import somebody else's circularity and call it independence.

**Write more synthetic attacks.** Cheap, and it makes the numbers move without
making them mean more. The corpus already knows this: `source` exists precisely
so that a synthetic result can be read as weaker evidence than a found one.

**Translate the existing corpus mechanically.** Would produce fifty documents
and one fact, since a machine translation of an attack this repository already
catches tests the translator, not the detector.

**Leave the languages alone.** The position ADR 0064 took, and it was right
*then* — the cost had not been measured. It is not a position that survives the
measurement coming back at zero.

## Consequences

The benign corpus now contains documents that will keep flagging, on purpose,
and their flags are load-bearing evidence rather than noise: if a future change
promotes `instruction_override` to enforceable, **this corpus refuses the
project's own threat model**, and the build fails on a document a reader can
open.

Five languages is five languages. Japanese, Korean, Arabic, Hindi and everything
else still match nothing, and there is a test asserting it so the gap stays
visible rather than being implied away by the five that work.

`plain_assertion` and `delayed_multi_step` remain at 0%. Nothing here touches
them; they need the classifier, which is off by default.

What would make us revisit: an external corpus with published labels. That
remains the thing that turns "0 of 111" from a number this project measured
about itself into one somebody else can check.
