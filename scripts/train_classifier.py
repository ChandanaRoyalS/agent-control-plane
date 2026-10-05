#!/usr/bin/env python3
"""Fit the learned injection classifier and write its weights (ADR 0075).

    uv sync --all-groups
    uv run python scripts/train_classifier.py           # fit, choose C and threshold, write
    uv run python scripts/train_classifier.py --check   # refit and compare with the committed model

Trains on `acp.corpus.training` train windows, chooses the regularisation strength
and the threshold on validation documents only, and never loads a sealed set. A
window of an attack document is a positive if it holds at least half of the planted
instruction, a negative if it holds none of it (that text is the benign context),
and is left out otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter

import numpy as np
import sklearn
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression

from acp.corpus.training import Example, assemble
from acp.firewall.learned import (
    MODEL_PATH,
    STRIDE,
    WINDOW,
    LearnedModel,
    features,
    from_json,
    normalise,
    windows,
)

GRID = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
TARGET_FPR = 0.01
MIN_DF = 2
SEED = 0
TOLERANCE = 1e-6


def labelled_windows(
    examples: list[Example],
) -> tuple[list[set[str]], list[int], list[float], Counter[str]]:
    rows: list[set[str]] = []
    labels: list[int] = []
    weights: list[float] = []
    notes: Counter[str] = Counter()
    for e in examples:
        text = normalise(e.text)
        span: tuple[int, int] | None = None
        if e.label == 1:
            planted = normalise(e.planted)
            start = text.find(planted) if planted else -1
            if start < 0:
                notes["attack without a locatable instruction, skipped"] += 1
                continue
            span = (start, start + len(planted))
        for start, window in windows(text):
            if span is None:
                label = 0
            else:
                overlap = max(0, min(span[1], start + len(window)) - max(span[0], start))
                if overlap >= (span[1] - span[0]) / 2:
                    label = 1
                elif overlap == 0:
                    label = 0
                else:
                    notes["window with part of an instruction, skipped"] += 1
                    continue
            rows.append(features(window))
            labels.append(label)
            weights.append(1.0)
    return rows, labels, weights, notes


def fit(rows: list[set[str]], labels: list[int], weights: list[float], c: float) -> LearnedModel:
    df: Counter[str] = Counter(f for row in rows for f in row)
    vocab = {f: i for i, f in enumerate(sorted(f for f, n in df.items() if n >= MIN_DF))}
    indptr, indices, data = [0], [], []
    for row in rows:
        scale = 1.0 / math.sqrt(len(row)) if row else 0.0
        cols = sorted(vocab[f] for f in row if f in vocab)
        indices.extend(cols)
        data.extend([scale] * len(cols))
        indptr.append(len(indices))
    matrix = csr_matrix((data, indices, indptr), shape=(len(rows), len(vocab)))
    model = LogisticRegression(
        l1_ratio=1.0,
        solver="liblinear",
        C=c,
        class_weight="balanced",
        random_state=SEED,
        max_iter=2000,
    )
    model.fit(matrix, np.asarray(labels), sample_weight=np.asarray(weights))
    names = sorted(vocab, key=vocab.__getitem__)
    weights = {names[i]: round(float(w), 8) for i, w in enumerate(model.coef_[0]) if w != 0.0}
    return LearnedModel(weights, round(float(model.intercept_[0]), 8), 0.5, 0.5, {})


def choose_threshold(model: LearnedModel, validation: list[Example]) -> tuple[float, float, float]:
    """The lowest threshold whose validation false-positive rate is at most TARGET_FPR."""
    benign = sorted(model.score(e.text) for e in validation if e.label == 0)
    attacks = [model.score(e.text) for e in validation if e.label == 1]
    allowed = math.floor(TARGET_FPR * len(benign))
    threshold = benign[-(allowed + 1)] + 1e-9 if benign else 0.5
    fpr = sum(s >= threshold for s in benign) / len(benign)
    recall = sum(s >= threshold for s in attacks) / len(attacks)
    return threshold, fpr, recall


def data_digest(examples: list[Example]) -> str:
    h = hashlib.sha256()
    for e in sorted(examples, key=lambda e: e.id):
        h.update(f"{e.id}\0{e.label}\0{e.text}\0".encode())
    return h.hexdigest()


def train() -> dict[str, object]:
    data = assemble()
    train_set, validation = list(data.train), list(data.validation)
    rows, labels, weights, notes = labelled_windows(train_set)
    print(f"{len(rows)} training windows ({sum(labels)} positive); {dict(notes)}", file=sys.stderr)
    best: tuple[float, float, LearnedModel, float, float] | None = None
    for c in GRID:
        model = fit(rows, labels, weights, c)
        threshold, fpr, recall = choose_threshold(model, validation)
        print(
            f"C={c:<5} features={len(model.weights):>6} threshold={threshold:.3f} "
            f"validation recall={recall:.1%} fpr={fpr:.1%}",
            file=sys.stderr,
        )
        if (
            best is None
            or recall > best[0]
            or (recall == best[0] and len(model.weights) < len(best[2].weights))
        ):
            best = (recall, c, model, threshold, fpr)
    if best is None:
        msg = "the grid is empty"
        raise SystemExit(msg)
    recall, c, model, threshold, fpr = best
    benign = [model.score(e.text) for e in validation if e.label == 0]
    attacks = [model.score(e.text) for e in validation if e.label == 1]
    enforce = max(benign) + 1e-6
    enforce_recall = sum(s >= enforce for s in attacks) / len(attacks)
    print(
        f"enforce threshold {enforce:.3f}: validation recall {enforce_recall:.1%}, fpr 0%",
        file=sys.stderr,
    )
    return {
        "intercept": model.intercept,
        "threshold": round(threshold, 8),
        "enforce_threshold": round(enforce, 8),
        "meta": {
            "C": c,
            "features": len(model.weights),
            "window": WINDOW,
            "stride": STRIDE,
            "target_fpr": TARGET_FPR,
            "validation": {"recall": round(recall, 4), "fpr": round(fpr, 4)},
            "validation_enforce": {"recall": round(enforce_recall, 4), "fpr": 0.0},
            "train_documents": len(train_set),
            "validation_documents": len(validation),
            "train_digest": data_digest(train_set),
            "validation_digest": data_digest(validation),
            "sklearn": sklearn.__version__,
        },
        "weights": dict(sorted(model.weights.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="refit and compare, write nothing")
    args = parser.parse_args()
    fitted = train()
    if args.check:
        committed = from_json(json.loads(MODEL_PATH.read_text(encoding="utf-8")))
        refit = from_json(fitted)
        same = (
            committed.weights.keys() == refit.weights.keys()
            and all(abs(committed.weights[k] - refit.weights[k]) < TOLERANCE for k in refit.weights)
            and abs(committed.threshold - refit.threshold) < TOLERANCE
            and abs(committed.enforce_threshold - refit.enforce_threshold) < TOLERANCE
        )
        print("The committed model matches a refit." if same else "FAILED: the refit differs.")
        return 0 if same else 1
    MODEL_PATH.write_text(json.dumps(fitted, indent=0, sort_keys=False) + "\n", encoding="utf-8")
    meta = fitted["meta"]
    print(f"Wrote {MODEL_PATH.name}: {meta}", file=sys.stderr)  # type: ignore[index]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
