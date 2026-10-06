# ADR 0076 — The learned classifier withholds only by choice

**Status:** accepted
**Date:** 2026-10-05

## Context

ADR 0075 measured a learned classifier once on sealed data. At its enforce
threshold it catches 64% of BIPIA's held-out attacks, which the patterns do not
withhold at all. It also flags 2.0% [0.5–4] of BIPIA's clean test documents and 1
of the 106 internal benign documents (an API reference page listing error
messages, scored 0.917).

ADR 0039 set the bar for a detector that may withhold: no hits on the benign
corpus. That bar is why `tool_name_mention` and `external_image` were demoted, and
it is code, not configuration, so a deployment cannot promote a noisy detector.
The learned classifier does not meet it. This ADR decides what it may do anyway.

## Decision

**A new setting, `ACP_FIREWALL_LEARNED`: `off`, `report` or `enforce`, default
`report`.** It only acts when the firewall is on (`ACP_FIREWALL_MODE` is not
`off`).

- `report` scores every tool result and adds a `learned_classifier` finding
  (family `plain_assertion`) when the score reaches the report threshold (0.464):
  MEDIUM below the enforce threshold (0.776), HIGH at or above it. It is never a
  trigger, so `would_refuse` keeps meaning "what this configuration would
  withhold". The count of HIGH `learned_classifier` findings is what switching to
  `enforce` would withhold.
- `enforce` makes a HIGH learned finding a trigger, like a finding from an
  `ENFORCEABLE` detector. It withholds only when `ACP_FIREWALL_MODE=enforce` too;
  under a `report` firewall it shows up as `would_refuse`.
- `off` skips the scoring.

**The bar it meets instead of ADR 0039's.** ADR 0039's zero-hit rule stays as it
is for the pattern detectors, and `ENFORCEABLE` is unchanged. The learned
classifier meets a different bar, and withholding is behind an explicit setting
because of it:

1. Both thresholds were chosen on validation data only, before any sealed set
   was scored (ADR 0075).
2. Its benign withholding rate was measured on data it never saw, with
   intervals, and is published next to the setting: 2.0% [0.5–4] of BIPIA's
   clean contexts, 0.9% [0–3] of the internal benign corpus.
3. It needs two settings to withhold, neither of them on by default.
4. Report mode, the default, records what enforcement would withhold, so a
   deployment measures its own rate on its own traffic before choosing.

A 2% false-withhold rate is a cost some deployments will take for 64% of polite
injections and others will not. That is an operator's decision, made with the
numbers, not this project's default.

**What is scored.** The text blocks of a tool result, joined, up to the
firewall's screening window (`max_chars`, 256 KiB). Past that, the result is
already withheld or reported for its unexamined tail (ADR 0069). The finding's
evidence is the score and the two thresholds, never document text.

**What is not scored: tool descriptions.** The classifier was never measured on
them, and a withheld tool cannot be called at all; catalogue screening stays
pattern-only.

**Cost.** About 1.1 ms per thousand characters, up to about 300 ms at the
screening window, in pure Python. `ainspect` therefore runs on a worker thread
whenever the model is attached, under the same capacity limiter as the Ollama
classifier (ADR 0053's bug class). The model is loaded when the gateway is built,
so a missing or corrupt model file fails at startup, not on a call. The startup
line `firewall.enabled` names the learned mode, its thresholds, and
`learned_classifier` among the enforceable detectors when it is.

**Amended by ADR 0080.** On AgentDojo's clean tool outputs, a set neither model was
trained on, the enforce threshold withheld 7 of 30 (23% [10–40]): ordinary emails and
a notice that ask the reader to do something. Point 2 above is the reason this is
opt-in; the published range now includes that number.

## Consequences

- With the default configuration every result now costs the scoring time. The
  default is `report` and not `off` for the reason ADR 0071 gives: a control that
  does not run is not measured. `ACP_FIREWALL_LEARNED=off` restores the previous
  cost.
- In report mode the logs gain MEDIUM findings at the report threshold, which
  flagged 6.6% of the internal benign corpus and 8.0% of BIPIA clean. These are
  findings, not decisions, and the decision line already reports every
  non-clean screening.
- The startup banner gains `firewall_learned`.
- Character-level disguises (homoglyphs, spacing, leetspeak, base64) still pass
  the classifier (ADR 0075). Enabling it does not close those.

## Alternatives considered

- **Add it to `ENFORCEABLE`.** Rejected: that makes a detector with a measured
  2% benign rate withhold for every deployment that enforces, and breaks ADR
  0039's rule that the set is held to zero benign hits.
- **Default `off`.** Rejected for the reason above; the cost is disclosed and
  one setting removes it.
- **A tunable threshold.** Rejected: the threshold is part of what was measured.
  A different number is an unmeasured model.
- **Score tool descriptions too.** Rejected until measured on descriptions.

## References

- ADR 0039 — which detectors may withhold
- ADR 0053 — blocking work off the event loop
- ADR 0069 — the unexamined tail
- ADR 0071 — controls that run by default
- ADR 0075 — the classifier and its sealed result
- `src/acp/firewall/decision.py`, `src/acp/runtime.py`
