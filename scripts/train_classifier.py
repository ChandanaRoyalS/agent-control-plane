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
import json
import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression

from acp.corpus.learned_eval import TARGET_FPR, operating_points
from acp.corpus.training import Example, assemble, data_digest, labelled_windows
from acp.firewall.learned import (
    MODEL_PATH,
    STRIDE,
    WINDOW,
    LearnedModel,
    features,
    from_json,
)

GRID = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
MIN_DF = 2
SEED = 0
TOLERANCE = 1e-6


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


def validation_scores(
    model: LearnedModel, validation: list[Example]
) -> tuple[list[float], list[float]]:
    """Benign and attack document scores on validation."""
    benign = [model.score(e.text) for e in validation if e.label == 0]
    attacks = [model.score(e.text) for e in validation if e.label == 1]
    return benign, attacks


def train(data_version: int = 1) -> dict[str, object]:
    data = assemble(data_version=data_version)
    train_set, validation = list(data.train), list(data.validation)
    labelled = labelled_windows(train_set)
    rows = [features(t) for t in labelled.texts]
    labels = labelled.labels
    weights = [1.0] * len(rows)
    print(
        f"{len(rows)} training windows ({sum(labels)} positive); skipped {dict(labelled.skipped)}",
        file=sys.stderr,
    )
    best: tuple[float, float, LearnedModel, float, float] | None = None
    for c in GRID:
        model = fit(rows, labels, weights, c)
        points = operating_points(*validation_scores(model, validation))
        threshold, fpr, recall = points.threshold, points.fpr, points.recall
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
    points = operating_points(*validation_scores(model, validation))
    enforce, enforce_recall = points.enforce_threshold, points.enforce_recall
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
            # Only recorded from version 2 on, so the version-1 model file is unchanged.
            **({"data_version": data_version} if data_version != 1 else {}),
        },
        "weights": dict(sorted(model.weights.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="refit and compare, write nothing")
    parser.add_argument(
        "--data-version",
        type=int,
        default=None,
        help="training data version (default: the committed model's)",
    )
    parser.add_argument("--out", type=Path, default=MODEL_PATH, help="where to write the model")
    args = parser.parse_args()
    committed = from_json(json.loads(MODEL_PATH.read_text(encoding="utf-8")))
    version = args.data_version or int(committed.meta.get("data_version", 1))
    fitted = train(version)
    if args.check:
        refit = from_json(fitted)
        same = (
            committed.weights.keys() == refit.weights.keys()
            and all(abs(committed.weights[k] - refit.weights[k]) < TOLERANCE for k in refit.weights)
            and abs(committed.threshold - refit.threshold) < TOLERANCE
            and abs(committed.enforce_threshold - refit.enforce_threshold) < TOLERANCE
        )
        print("The committed model matches a refit." if same else "FAILED: the refit differs.")
        return 0 if same else 1
    args.out.write_text(json.dumps(fitted, indent=0, sort_keys=False) + "\n", encoding="utf-8")
    meta = fitted["meta"]
    print(f"Wrote {args.out}: {meta}", file=sys.stderr)  # type: ignore[index]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
