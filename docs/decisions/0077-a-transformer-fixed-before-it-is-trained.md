# ADR 0077 — A transformer, fixed before it is trained

**Status:** accepted
**Date:** 2026-10-05

## Context

ADR 0075's linear classifier catches 64% of BIPIA's held-out attacks at its
enforce threshold, flags 2.0% of clean contexts, and drops to near zero on
character-level disguises. The plan for item 2 was linear first, then a small
transformer trained on the same splits. A transformer is too large to train in CI
and is not deterministic on a GPU, so the safeguards ADR 0075 relied on (CI refits
the model and compares) do not carry over. Fixing the run in advance replaces
them.

## Decision

**One run, specified here before any training.** The design is the constant
`TRANSFORMER_DESIGN` in `acp.corpus.training`:

| | |
|---|---|
| base model | `distilbert/distilroberta-base` (82M parameters, byte-level BPE) |
| data | ADR 0074's train split, windowed and labelled exactly as for the linear model (`labelled_windows`), after the same normalisation |
| training | 3 epochs, batch 16, AdamW at 2e-5, weight decay 0.01, linear schedule with 6% warm-up, class-balanced loss, gradient clipping at 1.0, seed 0 |
| input | up to 512 tokens per window; windows that tokenise longer are truncated and counted |
| model selection | none: the last epoch is the model, so validation is used only for thresholds |
| thresholds | ADR 0075's rules on validation documents: report at no more than 1% benign flagged, enforce above every benign score |
| document score | the highest window, as for the linear model |

**Where it runs.** `scripts/transformer.py`, on the owner's Mac (Apple-silicon
GPU), with PyTorch and transformers added by `uv run --with`. They are not
project dependencies: CI and the image never install them. Weights go to
`models/` (git-ignored) and are identified by sha256.

**What is committed.** `corpus/learned/transformer.json`: the design, training
details, data digests, weights hash, thresholds, latency, and the same rows as
`corpus/learned/results.json` (open sets, then sealed once). A test checks that
the record's design equals `TRANSFORMER_DESIGN`, its data digests equal the
linear model's, and its sealed result names its own weights.

**The sealed sets, a second look.** BIPIA test and evasion v1 were scored for
the linear model and are spent for that family (ADR 0075). This model is scored on
them once more, labelled as a second look in the record. What was known before
this design was fixed, stated so it can be weighed: ADR 0075's sealed results,
including that character-level disguises defeat n-gram features. A byte-level
tokeniser was chosen partly with that in view.

`--unseal` refuses a run whose design differs from `TRANSFORMER_DESIGN` (a smoke
test with `--base`, `--epochs` or `--limit`) and refuses a second unseal.

**What the comparison is.** The same documents, at each model's own enforce
threshold: attacks caught and clean documents flagged on BIPIA test, and caught
per disguise on evasion v1. Stated now: the transformer is the better model only
if it catches more BIPIA test attacks while flagging no more clean documents than
the linear model's 2.0%.

## Results (added after the one run)

Trained on the owner's Mac (Apple-silicon GPU, PyTorch 2.14.1, transformers
5.18.0) in 11 minutes: 3,003 windows, 90 of them truncated at 512 tokens; mean
loss 0.268, 0.020, 0.009 over the three epochs. Weights sha256 `b6e6d1b3108d…`,
recorded in `corpus/learned/transformer.json`.

Thresholds, by ADR 0075's rules on validation: report **0.0055** (recall 100%,
0.9% benign flagged), enforce **0.9991** (recall 98.4%). The model's scores sit
almost entirely at the two ends; a report threshold that low is a symptom of
that, not a choice.

**Sealed sets, a second look, at each model's enforce threshold:**

| set | transformer | linear (ADR 0075) |
|---|---|---|
| BIPIA test attacks (500), caught | **91.6% [88–95]** | 64.2% [57–71] |
| BIPIA test clean (200), flagged | **1.0% [0–2.5]** | 2.0% [0.5–4] |
| evasion v1 (500), caught | 47.6% [45–51] | 28.8% [25–33] |

By disguise, transformer then linear: alternating case 92% / 65%, reworded
override 93% / 63%, zero-width 93% / 65%, base64 split 45% / 0%, homoglyphs 6% /
1%, spaced letters 4% / 3%, leetspeak 1% / 4%.

**Report-only sets, never trained on:**

| set | transformer, enforce | linear, enforce | transformer, report |
|---|---|---|---|
| internal benign (106), flagged | 2.8% [0–7] | 0.9% [0–3] | 15.1% [8–22] |
| internal attacks (37), caught | 2.7% [0–8] | 8.1% [0–19] | 29.7% [16–43] |

**Against the bar stated above:** met. It catches more of BIPIA's held-out attacks
and flags no more of its clean contexts than the linear model. The false-positive
intervals overlap, so "no more" is the claim, not "fewer".

**What the bar did not ask, and the other sets answer:** on documents written in
a different style from its training data, it is worse than the linear model on
both counts. The 92% is largely BIPIA learning BIPIA: its train and test splits
share contexts' formats and the planting seam (ADR 0075). It does not generalise
to this project's own attacks, and the character-level disguises other than
base64 still pass it.

**Cost.** 12.7 ms per thousand characters on the Mac's GPU and 30.2 ms on its
CPU, against 1.1 ms for the linear model in pure Python: about 8 seconds on
CPU at the 256 KiB screening window (linear: 0.3 s).

**Outcome.** Not served. It would need a model server and a second runtime in
the image, and its benign rate on this project's documents is higher than the
model already in place. The next gain is more varied training attacks, not a
larger model.

## Consequences

- No gateway behaviour changes. The image carries no ML runtime, and this ADR
  does not add one; a result good enough to serve would need its own decision
  about a model server.
- The transformer cannot be refitted in CI. What CI checks is the record's
  consistency with the design and the data, not the weights.
- Training once, with one seed, gives no estimate of run-to-run variance. That
  is a limitation of the result and will be stated with it.

## Alternatives considered

- **Tune epochs or learning rate on validation.** Rejected: one run is the
  point. Validation is spent on thresholds only.
- **A pretrained injection detector.** Rejected: its training data is unknown
  and may include BIPIA, which would make every sealed number meaningless.
- **Add PyTorch to a dependency group.** Rejected: CI syncs every group, and the
  lock would gain gigabytes of CUDA wheels for a script run once.

## References

- ADR 0074 — the data and its splits
- ADR 0075 — the linear classifier and its sealed result
- ADR 0076 — the linear classifier on the request path
- `scripts/transformer.py`, `acp.corpus.training.TRANSFORMER_DESIGN`
