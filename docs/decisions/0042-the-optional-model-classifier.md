# ADR 0042 — The optional model classifier: a detector, never a decider

**Status:** accepted
**Date:** 2026-08-12

## Context

The pattern detectors (task 45) catch what deterministic rules can catch:
literal override phrases, encoded payloads, invisible characters, external
images. They cannot catch the families that carry no signal — a `plain_assertion`
that is a grammatical, correctly-spelled lie, or a `delayed_multi_step` payload
that only means anything across two documents. A model can read for *intent*
where a pattern reads for *shape*, so a classifier is the natural next detector.

But a classifier is the opposite of everything the pattern layer is built on. The
detectors are free, deterministic, explainable, and bounded against hostile
input (see `acp.firewall.detectors`), and the firewall's trustworthiness rests on
those properties. A model is slow, non-deterministic, opaque, and is being fed
text that is hostile by premise. Adding one carelessly would poison the
guarantees that make the false-positive rate meaningful.

## Decision

**The classifier is one more detector that emits findings, never a decider —
optional, absent-safe, confidence-capped, and its output untrusted.**

- **It emits `Finding`s, exactly like a pattern.** It never refuses. Detection
  and decision stay separate (ADR 0036), so the classifier's contribution shows
  up as findings the harness can score for a false-positive rate, not as a
  verdict that can only be measured by counting refusals after the damage.

- **Its confidence is capped at MEDIUM.** A model saying "this looks like an
  attack" is a weaker claim than a regex matching `<system>` literally. Capping
  it below HIGH means it cannot, on the current bar, enforce on its own — it is
  the *second signal* that can promote a demoted pattern (task 48's plan for the
  detectors the benign corpus knocked down), not a first mover that enforces from
  an opaque judgement.

- **Absence is a first-class, tested path.** The model may be missing, down, or
  slow. Each yields no findings, never an exception into screening. A firewall
  that failed closed on its optional layer is one a model outage takes offline;
  worse, one that failed *open* with an error would drop the pattern findings
  too. The client is injected precisely so this path is the one the tests
  exercise — the whole classifier is verified with no model at all.

- **The model's output is untrusted input.** The screened text is hostile, so a
  model's response after reading it is hostile too. `parse_verdict` treats any
  unexpected shape — prose, malformed JSON, an unknown family, an attempt to
  address the parser — as an abstention. A document that talks the model out of
  answering in JSON achieves only what an empty response would: no finding.

- **The input is bounded before the model sees it.** The screener bounds text;
  the classifier bounds again to what it sends, so a hostile document cannot turn
  one screening into an unbounded inference.

## What is and is not verified

The classifier's *logic* is fully tested with an injected function: inert without
a model, one MEDIUM finding on a clean verdict, no finding on garbage, no
exception on a transport failure, bounded input. The transport's *logic* is
tested with a mocked HTTP client: the prompt fences the document, the request
carries the shape Ollama expects, a missing response field degrades to empty.

What is **not** tested here is whether a live model classifies *well* — its
precision and recall. That is not a unit-test question; it is task 52's
measurement, run against a real Ollama over the development split, and reported
with the held-out split (task 50) kept sealed. This ADR deliberately ships the
mechanism with its safety proven and its accuracy unmeasured, in that order,
because a classifier that is unsafe is a bug and a classifier that is merely
unmeasured is the normal state before task 52.

## Alternatives considered

**A classifier that can refuse on its own.** Rejected — it collapses the
detection/decision separation that makes the false-positive rate measurable, and
it lets an opaque, non-deterministic signal withhold a legitimate document with
no pattern anyone can point at. The thing that gets a security control switched
off is exactly a refusal nobody can explain.

**HIGH confidence for a confident model.** Rejected — confidence here is the
firewall's claim, not the model's self-report, and the firewall's claim about a
model verdict is bounded by what a model verdict is worth. A model can be
confidently wrong; the cap is where that shows up.

**Required, not optional.** Rejected — a firewall that depends on a model service
to function is one that breaks in a way nobody configured, in every deployment
without a GPU. Optional and off-by-default keeps the deterministic layer the
floor and the model a bonus.

## Consequences

- New `acp.firewall.classifier` (`OllamaClassifier`, `parse_verdict`, pure and
  fully tested) and `acp.firewall.ollama` (the transport, tested with a mock).
  `Screener`, `Firewall`, and `firewall_for` gain an optional `classifier`;
  `build_firewall` constructs one when `ACP_FIREWALL_CLASSIFIER_ENABLED` is set.
- `detector_names` grows the classifier's name only when one is attached, so the
  coverage alarm (a bare screener equals `DETECTOR_NAMES`) is unchanged.
- Task 52's harness is the first thing to measure the classifier, against the
  development split, with the held-out split named and sealed.

## References

- ADR 0036 — detect before deciding (why a detector must not refuse)
- ADR 0039 — the benign corpus, and the detectors it demoted (the second-signal
  promotion path this classifier is meant to feed)
- ADR 0041 — the held-out split (what the classifier is measured against, and
  what it must never be tuned on)
