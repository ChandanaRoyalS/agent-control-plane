"""A learned injection classifier, scored in pure Python from committed weights (ADR 0075).

Logistic regression over character 3- to 5-grams and word uni- and bigrams of
normalised text, fitted by `scripts/train_classifier.py` and stored as
``learned_model.json``. A document is split into overlapping windows and scored as
its highest window, so one planted sentence in a long table is not averaged away.
Two thresholds travel with the weights, both chosen on validation data: ``threshold``
(report) at a benign false-positive rate of at most 1%, and ``enforce_threshold``
above every validation benign score, the only one allowed to withhold.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from itertools import pairwise
from pathlib import Path
from typing import Any, Final

WINDOW: Final = 1500
STRIDE: Final = 1200
"""Windows overlap by 300 characters, so an instruction shorter than that is whole in one."""

CHAR_NGRAMS: Final = (3, 4, 5)
MODEL_PATH: Final = Path(__file__).with_name("learned_model.json")

_SPACE = re.compile(r"\s+")
_WORD = re.compile(r"\w+")


def normalise(text: str) -> str:
    """NFKC, case-folded, invisible format characters removed, whitespace collapsed.

    Fixed before any evaluation: Unicode format characters (category Cf, such as
    zero-width spaces) carry no visible text, so dropping them is not tuning.
    Homoglyphs are deliberately not folded.
    """
    folded = unicodedata.normalize("NFKC", text).casefold()
    visible = "".join(c for c in folded if unicodedata.category(c) != "Cf")
    return _SPACE.sub(" ", visible).strip()


def windows(text: str) -> Iterator[tuple[int, str]]:
    """``(start, window)`` pairs over normalised text; at least one, possibly empty."""
    if len(text) <= WINDOW:
        yield 0, text
        return
    start = 0
    while True:
        yield start, text[start : start + WINDOW]
        if start + WINDOW >= len(text):
            return
        start += STRIDE


def features(window: str) -> set[str]:
    """Every feature present in one normalised window."""
    found = {f"c{n}:{window[i : i + n]}" for n in CHAR_NGRAMS for i in range(len(window) - n + 1)}
    words = _WORD.findall(window)
    found.update(f"w:{w}" for w in words)
    found.update(f"b:{a} {b}" for a, b in pairwise(words))
    return found


@dataclass(frozen=True, slots=True)
class LearnedModel:
    weights: Mapping[str, float]
    intercept: float
    threshold: float
    enforce_threshold: float
    meta: Mapping[str, Any]

    def window_score(self, window: str) -> float:
        present = features(window)
        if not present:
            return _sigmoid(self.intercept)
        total = sum(self.weights.get(f, 0.0) for f in present)
        return _sigmoid(self.intercept + total / math.sqrt(len(present)))

    def score(self, text: str) -> float:
        """The probability-like score of the most suspicious window."""
        return max(self.window_score(w) for _, w in windows(normalise(text)))

    def flags(self, text: str) -> bool:
        return self.score(text) >= self.threshold

    def withholds(self, text: str) -> bool:
        return self.score(text) >= self.enforce_threshold


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def from_json(raw: Mapping[str, Any]) -> LearnedModel:
    return LearnedModel(
        weights={str(k): float(v) for k, v in raw["weights"].items()},
        intercept=float(raw["intercept"]),
        threshold=float(raw["threshold"]),
        enforce_threshold=float(raw["enforce_threshold"]),
        meta=dict(raw.get("meta", {})),
    )


@cache
def load_model(path: Path = MODEL_PATH) -> LearnedModel:
    """The committed model, read once per process."""
    return from_json(json.loads(path.read_text(encoding="utf-8")))
