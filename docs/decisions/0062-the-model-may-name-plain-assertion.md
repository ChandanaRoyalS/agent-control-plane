# ADR 0062 — The model may name `plain_assertion`

**Status:** accepted
**Date:** 2026-10-04

## Context

ADR 0060 found that the classifier's prompt offered the model seven families
and `parse_verdict` accepted five. A verdict naming `plain_assertion` or
`delayed_multi_step` was discarded without a trace — 3 of 284 calls in the
measured run, alongside one invented family. `plain_assertion` is the family the
classifier was added for (ADR 0042: a model reads intent where a pattern reads
shape), and ADR 0061 then measured the cost of missing it on attacks nobody here
wrote: 0 of 459 polite InjecAgent documents caught by the patterns.

So the one answer the model exists to give was the one answer the firewall threw
away.

## Decision

**`plain_assertion` becomes a reportable `Family`, reported only by the model;
the prompt's family list is derived from `Family`, so prompt and parser are one
taxonomy by construction.**

- `Family.PLAIN_ASSERTION` exists. No pattern detector reports it, and none
  will: there is no shape to match.
- `acp.firewall.ollama` builds its family list from `Family` instead of typing
  it out, and tells the model to use `plain_assertion` for a polite request or
  false claim when nothing else fits. A test asserts every offered family
  survives `parse_verdict` and every reportable family is offered.
- `delayed_multi_step` is no longer offered. Screening is per result (ADR 0036),
  so no detector — model included — ever sees the two documents the attack
  needs. It stays an attack family with no detector, and is now the only one.
- A verdict naming a family outside `Family` (an invention) is still discarded,
  and `scripts/evaluate_classifier.py` still counts it as `DISCARDED`.

## Alternatives considered

- **Map an unknown family to a default.** Every candidate default is a claim the
  model did not make; precision for that family would absorb the guesses.
- **Accept any attack verdict regardless of family.** A finding needs a family
  for the harness to slice; a family-less finding would be uncountable.
- **Leave the taxonomy and drop `plain_assertion` from the prompt.** Removes the
  defect by removing the only family the classifier could add.

## Consequences

- The model's `plain_assertion` verdicts now reach the firewall as MEDIUM
  findings. They cannot withhold anything on their own (the MEDIUM cap, ADR
  0042), so the change adds signal, not enforcement.
- The pattern-only numbers — `corpus/eval-baseline.json`, the InjecAgent
  baseline, every CI gate — do not move: no pattern reports the new family.
- Whether the model's `plain_assertion` verdicts are *right* is measured, not
  assumed: `make eval-classifier` and `ACP_FIREWALL_CLASSIFIER_ENABLED=1 make
  eval-external`, before anything is allowed to act on them.

## References

- ADR 0040 — the families nothing catches
- ADR 0042 — the optional model classifier
- ADR 0060 — where the defect was found
- ADR 0061 — what missing `plain_assertion` costs on external attacks
