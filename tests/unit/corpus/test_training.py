"""The classifier's splits: nothing it learns from or tunes on is scored (ADR 0074)."""

from __future__ import annotations

import pytest

from acp.corpus.external import load_external_split
from acp.corpus.loader import default_root
from acp.corpus.training import VALIDATION_SHARE, Example, assemble, check_disjoint


def test_no_group_or_text_is_shared_between_any_two_sets() -> None:
    """Includes the sealed sets, merged: the evasion corpus shares its groups with the
    BIPIA test split by design. This compares texts; it does not score anything."""
    data = assemble(unseal=True)
    sealed = [e for examples in data.sealed.values() for e in examples]
    check_disjoint(
        {"train": data.train, "validation": data.validation, **data.report, "sealed": sealed}
    )


def test_sealed_sets_are_empty_unless_asked_for() -> None:
    assert assemble().sealed == {}


def test_injecagent_held_out_groups_are_never_in_the_pool() -> None:
    sealed = {
        d.group for d in load_external_split(default_root() / "external" / "injecagent").heldout
    }
    data = assemble()
    assert not sealed & {e.group for e in (*data.train, *data.validation)}


def test_validation_is_about_one_fifth_of_the_pool() -> None:
    data = assemble()
    share = len(data.validation) / (len(data.train) + len(data.validation))
    assert abs(share - 1 / VALIDATION_SHARE) < 0.06


def test_both_labels_are_in_train_and_validation() -> None:
    data = assemble()
    for split in (data.train, data.validation):
        assert {e.label for e in split} == {0, 1}


def test_check_disjoint_names_the_overlap() -> None:
    a = Example("x", "same text", 1, "g1", "s")
    b = Example("y", "same text", 0, "g2", "s")
    with pytest.raises(ValueError, match="text is in both"):
        check_disjoint({"one": [a], "two": [b]})
