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
