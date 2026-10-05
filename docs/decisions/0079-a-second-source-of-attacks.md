# ADR 0079 — A second source of attacks, and the rule for using it

**Status:** accepted
**Date:** 2026-10-05

## Context

Both learned models learned BIPIA's style. The linear model catches 64% of BIPIA's
held-out attacks and 8% of this project's own; the transformer catches 92% and 3%
(ADR 0075, ADR 0077). The training data had one source of planted attacks in documents
(BIPIA) and one of tool responses (InjecAgent), and the models fit them.

AgentDojo (Debenedetti et al., NeurIPS 2024, MIT) is a different shape: four agent
environments (banking, Slack, travel, workspace) whose emails, files, reviews and web
pages carry named injection vectors, attacker goals written as injection tasks, and five
fixed attack templates. It is the closest public match to what this gateway screens:
tool results with an instruction inside a field.

This ADR adds it as data version 2 and fixes, before any model is trained on it, what
that model must do to replace the one the gateway uses.

## Decision

**The import.** From the pinned PyPI wheel (`agentdojo` 0.1.35, SHA-256 in
`scripts/import_agentdojo.py`), read as a zip and never installed:

- each object a tool would return, rendered as `key: value` lines; one with a text
  field of at least 60 characters is a clean document, its vectors at their defaults;
- each attacker goal (the latest version of each injection task, de-duplicated by
  text) planted in every injection vector of its suite, once per template;
- the templates are AgentDojo's own, checked against the pinned source at import.

1,698 documents: 1,604 attacks over 35 goals and 38 vectors, and 94 clean objects.

**The split.** One goal in three is held out by salted hash of its text; clean objects
are split the same way. AgentDojo's own attack, `important_instructions`, is never
trained on: it appears only in the held-out half, so that set measures one wrapper no
model here has seen beside four it has. Held out: 11 goals, 500 attacks, 30 clean
documents, sealed in `corpus/external/agentdojo/heldout.txt`.

Known weaknesses, stated now:

- The four shared templates are fixed strings; a model can learn them rather than
  the goals. Results are reported per template, and the held-out template is the
  honest one.
- Held-out attacks are planted in the same 38 objects as training attacks; only the
  goal is new. 94 clean documents is too few for a tight false-positive estimate.
- Eleven held-out goals make the attack interval wide.

**Data versions.** `assemble(data_version=2)` adds AgentDojo's training half to the
pool and its held-out half to the sealed sets. Version 1 stays the default: it is what
the committed model was trained on, and CI checks that.

**The rule, fixed before any training.** A model "v2" is trained on data version 2 by
exactly ADR 0075's procedure (features, normalisation, windows, grid, both threshold
rules). It replaces the gateway's model only if, at each model's own enforce threshold,
all three hold:

1. **It catches more of the internal attacks** (37, never trained on) than v1's 3.
2. **It withholds no more of the internal benign corpus** (106) than v1's 1.
3. **It withholds no more of BIPIA's clean test contexts** than v1's 4 of 200.

The internal sets are the only ones both models are out of distribution on, which is
why they decide. Also reported, once, and not part of the rule: both models on the
AgentDojo held-out set (a first look for both, in distribution only for v2), per
template; and v2 on BIPIA test and evasion v1, a third look at those sets.

If v2 fails the rule, v1 stays, and v2's numbers are recorded beside it.

## Consequences

- No behaviour changes in this ADR: no model is trained here.
- The next change trains v2, scores both models once, applies the rule above, and
  either replaces `learned_model.json` (with the same CI refit check) or records why
  not.

## References

- ADR 0074 — the data and its sealing
- ADR 0075 — the linear model and its procedure
- ADR 0077 — the transformer
- `src/acp/corpus/agentdojo.py`, `scripts/import_agentdojo.py`,
  `corpus/external/agentdojo/SOURCE.md`
