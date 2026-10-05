"""The learned-versus-patterns comparison, on hand-built examples."""

from __future__ import annotations

from acp.corpus.learned_eval import as_json, compare
from acp.corpus.training import Example
from acp.firewall.learned import LearnedModel

MODEL = LearnedModel({"w:transfer": 40.0}, -4.0, 0.5, 0.9, {})


def test_rows_split_by_label_and_count_each_measure() -> None:
    examples = [
        Example("a1", "please transfer the funds now", 1, "g1", "t"),
        Example("a2", "nothing to see", 1, "g2", "t"),
        Example("b1", "quarterly report attached", 0, "b1", "t"),
    ]
    attacks, benign = compare("set", examples, MODEL, resamples=50)
    assert (attacks.kind, benign.kind) == ("attacks", "benign")
    assert attacks.learned.successes == 1
    assert attacks.learned.total == 2
    assert benign.learned.successes == 0
    [row, _] = as_json([attacks, benign])
    learned = row["learned"]
    assert isinstance(learned, dict)
    assert (learned["hits"], learned["total"], learned["rate"]) == (1, 2, 0.5)
