# ADR 0074 — The classifier's data, fixed before the classifier

**Status:** accepted
**Date:** 2026-10-05

## Context

The external review's item 2 asks for a learned classifier on the enforcement path,
measured with intervals on data its author did not shape, and an evasion corpus to
test it against (W9). Every number this project publishes about the firewall rests
on keeping what a detector was built from apart from what it is scored on (ADR 0041,
0061). A trained model makes that harder to keep and easier to break without
noticing: one shared sentence between training and test data turns memorisation
into a detection rate. So the data, the splits and the leakage checks come first,
in their own change, before any model exists.

## Decision

**Sources.**

| source | used for | why |
|---|---|---|
| InjecAgent development groups (ADR 0061), poisoned and with the instruction removed | train, validation | Tool responses with planted instructions; the removed-instruction copy forces the model to learn the instruction, not the template. Held-out v2 groups are excluded. |
| BIPIA train split (Microsoft, MIT; contexts CC BY-SA), planted and clean | train, validation | Emails, tables and Stack Overflow answers, a different author and shape from InjecAgent. |
| CPython standard-library docstrings (PSF) | train, validation | Benign technical prose full of imperatives, the hard negative a polite-injection detector must not flag. |
| internal benign corpus (106) and development attacks (37) | report only | Never trained on, so the false-positive yardstick (ADR 0047) stays independent. |
| BIPIA test split, 500 attacks and 200 clean | sealed | Instructions BIPIA's authors kept apart from train; no instruction is shared. |
| evasion corpus v1, 500 | sealed | Each BIPIA test attack disguised one way (below). |

**BIPIA construction.** Every context once as a clean document; every instruction
planted in four contexts at the start, middle or end, by a fixed rule over indices
(`acp.corpus.bipia`). Text attacks go into emails and tables, code attacks into
Stack Overflow answers, as BIPIA does. Eleven train contexts that BIPIA repeats in
its test split are dropped from train; the leakage test found the first of them.

**Evasion corpus v1 (W9).** Seven surface transforms of the planted instruction only:
Cyrillic homoglyphs, zero-width characters, spaced letters, leetspeak, alternating
case, base64 split across a line, and eight rewordings of "ignore previous
instructions" that the shipped patterns do not name. Assigned by index, about 71
documents each. Paraphrase and translation need a model and are not in v1.

**Splits.** By group: one attacker instruction, one context, or, for InjecAgent's
removed-instruction templates, the text itself. Validation is one group in five by
salted hash. `check_disjoint` fails if any group or exact text is in two sets, and a
test runs it over every set, the sealed ones included (it compares, it scores nothing).

**Sealing.** `corpus/external/bipia/heldout.txt` lists the BIPIA test groups. They
and the evasion corpus are not loaded unless `assemble(unseal=True)` is called, and
they are scored once, by the classifier change, with the result recorded.

## Disclosure

While checking the evasion output during this change, the first seven evasion
documents were printed: seven disguised BIPIA test instructions (renaming files,
backing up a folder, and similar). No model existed, and no model choice, feature or
threshold has been made since. Recorded so the sealed result can be weighed with
that in view.

## Alternatives considered

- **Train on the internal benign corpus too.** More benign data, but then the
  project's false-positive number would measure memory.
- **Use InjecAgent's held-out v2 as the test set.** It was scored once and spent
  (ADR 0064); a second look would not be held out.
- **Random document splits.** BIPIA and InjecAgent are cross products of
  instructions and contexts, so a random split puts the same sentence on both sides.

## Consequences

- The repository gains about 5 MB of corpus files. BIPIA and the evasion corpus
  regenerate byte for byte from the pinned commit; the docstrings regenerate from
  the same Python version, which `SOURCE.md` records.
- Train is 2,378 documents (1,172 attacks, 1,206 benign); validation is 511 (246,
  265).
- No firewall behaviour changes. The classifier and its measurement are the next
  change.

## References

- ADR 0041 — held-out splits
- ADR 0047 — the benign baseline
- ADR 0061 — InjecAgent, split by attacker instruction
- ADR 0064 — held-out v2 scored once
- `src/acp/corpus/bipia.py`, `src/acp/corpus/evasion.py`, `src/acp/corpus/training.py`
- `scripts/import_bipia.py`, `scripts/import_stdlib_benign.py`
