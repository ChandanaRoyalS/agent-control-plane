# ADR 0069 — The unexamined tail is the trigger

**Status:** accepted; amends [ADR 0036](0036-detect-before-deciding-and-count-the-false-positives.md)
**Date:** 2026-10-05

## Context

ADR 0036 bounded the screener's input at 256 KB and said why: the text is
attacker-controlled, every pattern is linear, and a bound is what keeps the
screening pass from being a denial-of-service lever. It also said the one thing
that makes a bound safe — "truncation is reported, because a screener that
silently examined the first N bytes would be a control with a documented
bypass: put the payload at the end." `Screening.clean` was defined as no
findings *and* nothing unexamined, and the decision layer used the second half
to refuse to **cache** a truncated result.

It did not use it to refuse the result. The decision layer withheld on
`triggers_for(screening)`, which read only the findings; a truncated screening
with no findings in its window produced no triggers, and in enforce mode the
document was served, marked uncacheable, with a log line. An outside review
sent 256 KB of padding followed by a bidirectional override and an instruction,
and the gateway served it. The documented bypass was the actual bypass.

The project's own code comment gave the reason it had been left that way:
"refusing a document for being long would be a false positive with an obvious
trigger." That is true, and it is the wrong thing to weigh. A false positive on
a long document costs one caller one retry with a shorter result; the same
caller can ask for the document in pages. A payload past the window costs the
one thing the enforcement bar exists to prevent, and it costs it to an attacker
who knows the bound — which is everyone, since the bound is in the source.

## Decision

**In enforce mode a screening that did not read the whole document withholds
it.** `triggers_for` returns, in addition to any HIGH finding from an
enforceable detector, a trigger named `unexamined_tail` whenever
`screening.truncated` is set. The trigger carries the window size as its
evidence so the refusal notice says why. Report mode treats it as it treats any
trigger: the document is served, the decision is logged as `would_refuse`, and
the result is not cached (that half of ADR 0036's answer stands).

- **It is a trigger, not a detector.** It is not on `ENFORCEABLE` and not in
  `DETECTOR_NAMES`, because nothing ran: it is not a claim about the text, it is
  the absence of one. The registry alarm that every enforceable detector must
  be able to produce a HIGH finding does not apply to it and should not.
- **The window does not move.** Raising `MAX_SCREENED_CHARS` would relocate the
  bypass, not remove it, and a larger window is a larger lever for the
  denial-of-service the bound exists to limit. 256 KB stays; what changes is
  what the bound *means* once crossed.
- **The corpus carries the attack.** `payload-past-the-window.txt` in the
  obfuscation family is 256 KB of ordinary prose followed by the same
  bidirectional override `bidi-override-instruction.txt` uses, expected
  `withheld`. The evaluation baseline moved from 7 to 8 obfuscation attacks and
  from 4 to 5 withheld; the diff is in the same commit. The harness counts a
  withheld document as detected whatever withheld it, because `withheld` must
  never exceed `detected`.
- **The mutation harness breaks it on purpose.** A seventh mutation in
  `mutate_refusal.py` removes the trigger and must be caught by the end-to-end
  test that sends the padded bytes through a real gateway and asserts they do
  not come back.

## Alternatives considered

- **Screen the whole document, no window.** Removes the bypass by removing the
  bound, and hands an upstream a linear-time lever of whatever size it likes.
  The window is the right shape; the error was in what happened past it.
- **Screen the head and the tail.** Catches the reviewer's exact exploit and
  misses the payload placed in the middle. A control shaped around one exploit
  is the thing ADR 0036 was written to avoid.
- **Fence a truncated result instead of withholding it.** Provenance framing
  (ADR 0037) tells the model the text is data. An instruction past the window
  is still an instruction inside the fence, and the model is the one deciding
  whether to follow it.
- **A separate, larger bound for enforce mode.** Two bounds are two things to
  reason about and the second is still a bound with a tail.

## Consequences

- A tool result over 256 KB of text is **withheld in enforce mode**, with a
  refusal notice naming the window. A deployment whose upstream legitimately
  returns results that large sees them refused and should page them; report
  mode shows how many that is before enforcement is turned on, as it does for
  every other trigger.
- The threat model's §6.1 table: obfuscation 7/8 detected, 5 withheld. The
  corpus gained one attack, written by the detector's author, so this is a
  behaviour check with a recorded expectation and not a generalisation
  estimate (ADR 0065 draws the same line).
- The enforcement bar is no longer "two detectors": it is two detectors and one
  condition on the screening. The README's description of what enforce mode
  withholds should say so, and does.
- No new setting.

## References

- ADR 0036 — the bound, and the sentence this ADR makes true
- ADR 0037 — why a fence is not an answer here
- ADR 0039 — the bar the two enforceable detectors cleared
- `tests/integration/test_firewall_refusal.py` — the padded bytes do not come back
- `scripts/mutate_refusal.py` — the seventh mutation
