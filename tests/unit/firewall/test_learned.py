"""The learned classifier's pure-Python scorer and the committed model (ADR 0075)."""

from __future__ import annotations

import hashlib
import json
import math
from itertools import pairwise

import pytest

from acp.corpus.loader import default_root
from acp.corpus.training import TRANSFORMER_DESIGN, assemble, data_digest
from acp.firewall.learned import (
    MODEL_PATH,
    STRIDE,
    WINDOW,
    LearnedModel,
    features,
    from_json,
    load_model,
    normalise,
    windows,
)

RESULTS = default_root() / "learned" / "results.json"


def tiny(weights: dict[str, float], intercept: float = 0.0) -> LearnedModel:
    return LearnedModel(weights, intercept, 0.5, 0.9, {})


def test_normalise_folds_case_drops_invisible_characters_and_collapses_space() -> None:
    assert normalise("Ig\u200bNORE   the\nRules") == "ignore the rules"


def test_normalise_does_not_fold_homoglyphs() -> None:
    """Decided before evaluation: look-alike letters stay distinct (ADR 0075)."""
    assert normalise("\u0430") != "a"


def test_windows_cover_the_whole_text_with_overlap() -> None:
    text = "x" * (WINDOW * 3)
    spans = [(s, s + len(w)) for s, w in windows(text)]
    assert spans[0][0] == 0
    assert spans[-1][1] == len(text)
    assert all(b[0] - a[0] == STRIDE for a, b in pairwise(spans))
    assert list(windows("short")) == [(0, "short")]


def test_features_hold_char_ngrams_words_and_bigrams() -> None:
    found = features("send it")
    assert {"c3:sen", "c4:send", "c5:send ", "w:send", "w:it", "b:send it"} <= found


def test_a_window_score_is_the_logistic_of_its_scaled_weight_sum() -> None:
    model = tiny({"w:send": 2.0}, intercept=-1.0)
    n = len(features("send"))
    expected = 1 / (1 + math.exp(-(-1.0 + 2.0 / math.sqrt(n))))
    assert model.window_score("send") == pytest.approx(expected)


def test_a_document_scores_as_its_worst_window() -> None:
    model = tiny({"w:attack": 50.0})
    long = "calm words " * 400 + "attack"
    assert model.score(long) == pytest.approx(
        model.window_score(normalise(long)[-WINDOW:]), rel=0.5
    )
    assert model.score(long) > model.score("calm words " * 400)


def test_the_committed_model_loads_with_ordered_thresholds() -> None:
    model = load_model()
    assert model.weights
    assert 0.0 < model.threshold <= model.enforce_threshold < 1.0


def test_the_committed_model_was_trained_on_todays_data() -> None:
    """A change to the corpora or the splits must be followed by a retrain."""
    model = load_model()
    data = assemble()

    assert model.meta["train_digest"] == data_digest(data.train)
    assert model.meta["validation_digest"] == data_digest(data.validation)


def test_the_sealed_result_belongs_to_the_committed_model() -> None:
    """The sealed sets were scored once, with this exact file; a retrained model
    has no sealed result and must not borrow this one."""
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert results["sealed"], "the sealed sets have not been scored"
    assert results["sealed_on"] == hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()


def test_from_json_round_trips() -> None:
    raw = {"weights": {"w:a": 1}, "intercept": 0, "threshold": 0.4, "enforce_threshold": 0.6}
    model = from_json(raw)
    assert model.weights == {"w:a": 1.0}
    assert model.meta == {}


TRANSFORMER_RECORD = default_root() / "learned" / "transformer.json"


@pytest.mark.skipif(not TRANSFORMER_RECORD.exists(), reason="the transformer has not been scored")
def test_the_transformer_record_is_the_preregistered_run_on_the_same_splits() -> None:
    """ADR 0077: one run of the design fixed before training, on the linear model's
    exact data, with its sealed result tied to its weights."""
    record = json.loads(TRANSFORMER_RECORD.read_text(encoding="utf-8"))
    linear = load_model()

    assert record["model"]["design"] == TRANSFORMER_DESIGN
    assert record["model"]["train_digest"] == linear.meta["train_digest"]
    assert record["model"]["validation_digest"] == linear.meta["validation_digest"]
    assert record["sealed"], "the sealed sets have not been scored"
    assert record["sealed_on"] == record["model"]["weights_sha256"]
