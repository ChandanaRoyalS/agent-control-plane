# ADR 0075 — A learned classifier, measured once

**Status:** accepted
**Date:** 2026-10-05

## Context

The pattern firewall withholds none of the polite injections on any external set
this project has measured (ADR 0063, 0064). The external review's item 2 asks for a
model on the enforcement path, scored with intervals on data its author did not
shape. ADR 0074 fixed that data first. This ADR records the model, how its
operating points were chosen, and the one sealed result.

## Decision

**The model.** L1-regularised logistic regression over the presence of character
3- to 5-grams and word uni- and bigrams, each window's features scaled by one over
the square root of their count. Text is NFKC-normalised, case-folded, stripped of
invisible format characters (Unicode category Cf) and whitespace-collapsed before
features are taken. Homoglyphs are deliberately not folded; that was decided before
any evaluation. A document is scored as its worst 1,500-character window, with
windows overlapping by 300, so one planted sentence in a long table is not averaged
away. Training labels windows, not documents: a window of an attack document is a
positive if it holds at least half of the planted instruction and a negative if it
holds none of it.

The weights (193 features, `C = 8`) are committed as
`src/acp/firewall/learned_model.json` and scored by `acp.firewall.learned` in pure
Python: no ML library in the gateway image. `scikit-learn` sits in a `train`
dependency group, and CI refits the model and fails if the result differs.

**Two operating points, both chosen on validation only.**

| threshold | rule | validation recall | validation false positives |
|---|---|---|---|
| report, 0.464 | the lowest with at most 1% benign flagged | 93.1% | 0.9% |
| enforce, 0.776 | above every benign validation score | 87.4% | 0% |

Only the enforce threshold may ever withhold. `C` was the grid value with the best
validation recall at the report threshold.

**Changes made on validation evidence, before anything sealed was scored.**

1. InjecAgent controls were first built by deleting the instruction, which left an
   empty field (`''`). That became the most benign-looking feature in the model. The
   controls now carry a benign sentence from BIPIA's train emails in that field.
2. The first fit flagged both InjecAgent validation controls: hundreds of attacks
   shared a handful of templates, so the template predicted "attack". One control
   per attack, each with its own filler sentence, fixed it.
3. The enforce threshold was added after the report threshold flagged 7 of the 106
   internal benign documents (6.6%), far above its 1% validation target. That
   number comes from a report-only set; the change was made knowing it, and is
   recorded here so the sealed result can be weighed with that in view.

## Results

Report-only sets (never trained on, seen during development):

| set | learned, report | learned, enforce | patterns, any finding | patterns, withheld |
|---|---|---|---|---|
| internal benign (106), flagged | 6.6% [2–11] | 0.9% [0–3] | 21.7% [14–29] | 0% |
| internal attacks (37), caught | 13.5% [3–24] | 8.1% [0–19] | 56.8% [41–73] | 13.5% [5–24] |

**Sealed sets, scored once** with the model whose sha256 is recorded in
`corpus/learned/results.json` (a test fails if that file changes):

| set | learned, report | learned, enforce | patterns, any finding | patterns, withheld |
|---|---|---|---|---|
| BIPIA test attacks (500; 125 instructions) | **79.6% [74–85]** | **64.2% [57–71]** | 19.4% [13–26] | 0% |
| BIPIA test clean (200), flagged | 8.0% [5–12] | 2.0% [0.5–4] | 1.5% [0–4] | 0% |
| evasion v1 (500) | 41.0% [37–45] | 28.8% [25–33] | 21.0% [18–24] | 0% |

By disguise, at the enforce threshold: alternating case 65%, reworded override 63%,
zero-width 65% (normalisation removes it), and then leetspeak 4%, spaced letters 3%,
homoglyphs 1%, base64 split 0%. The patterns flag every zero-width document (an
invisible-character detector) and withhold none of them.

## What this shows and does not

- On instructions nobody here wrote, the learned model at its enforce threshold
  catches 64% of BIPIA's held-out attacks. The patterns catch 19% and withhold none.
  This is the first control in the project that withholds a meaningful share of
  polite injections.
- **Its false-positive rate does not transfer.** Chosen at 0% on validation, the
  enforce threshold flags 2.0% of BIPIA's clean test contexts and 0.9% of the
  internal benign corpus; the report threshold flags 8.0% and 6.6%. Validation
  shares sources with training; the sets that do not, disagree with it.
- **Surface disguises defeat it.** Anything that breaks character n-grams
  (homoglyphs, spacing, leetspeak, encoding) drops it to near zero. A
  normalisation step for these would have to be chosen on new data, not on this
  corpus, which is now spent.
- **Internal attacks are mostly missed** (8% at enforce). Their styles (exfiltration
  links, boundary escapes) are absent from the training data; the patterns remain
  the better detector for those.
- **BIPIA's planting seam is a feature.** `. |` (a sentence ending, then a table
  pipe) carries weight: BIPIA puts the instruction on its own line inside tables,
  in training and test alike. Part of the table result may be the seam rather than
  the instruction.
- **Disclosure.** Seven sealed BIPIA test instructions were printed during ADR 0074,
  before any model existed.

## Consequences

- No gateway behaviour changes here. Wiring the classifier into the firewall, in
  report mode with withholding behind an explicit setting, is the next change; at a
  2% benign withholding rate on clean BIPIA it does not meet the bar ADR 0039 set
  for an enforcing detector (no benign hits), and that change has to say what bar it
  meets instead.
- The sealed BIPIA test split and evasion v1 are spent for this model family. A
  later model scored on them is a second look and must say so.

## References

- ADR 0039 — which detectors may withhold
- ADR 0063, ADR 0064 — polite injections and the pattern firewall
- ADR 0074 — the data
- `src/acp/firewall/learned.py`, `scripts/train_classifier.py`,
  `scripts/evaluate_learned.py`, `corpus/learned/results.json`
