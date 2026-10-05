"""The learned-versus-patterns comparison, on hand-built examples."""

from __future__ import annotations

from acp.corpus.learned_eval import as_json, compare, open_sets, operating_points, sealed_sets
from acp.corpus.training import Example, assemble
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


def test_operating_points_follow_adr_0075s_rules() -> None:
    benign = [i / 100 for i in range(100)]  # 0.00 .. 0.99
    attacks = [0.5, 0.985, 0.995, 1.0]

    points = operating_points(benign, attacks, target_fpr=0.01)

    assert points.fpr <= 0.01
    assert sum(b >= points.threshold for b in benign) == 1
    assert points.enforce_threshold > max(benign)
    assert points.recall == 0.75
    assert points.enforce_recall == 0.5


def test_open_and_sealed_sets_stay_apart() -> None:
    data = assemble()

    assert set(open_sets(data)) >= {"internal_benign", "internal_attacks"}
    assert all(name.startswith("validation/") for name in list(open_sets(data))[:3])
    assert sealed_sets(data) == {}
