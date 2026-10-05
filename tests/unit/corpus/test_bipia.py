"""BIPIA's construction rule, and the committed import it produced (ADR 0074)."""

from __future__ import annotations

from collections import Counter

from acp.corpus.bipia import (
    ATTACK,
    CLEAN,
    CONTEXTS_PER_ATTACK,
    Context,
    Instruction,
    build,
    default_bipia_dir,
    dump,
    load_bipia,
    placements,
    plant,
)
from acp.corpus.heldout import load_heldout_manifest

CONTEXTS = {
    "email": [Context("email", 0, "a\nb\nc\nd")],
    "table": [Context("table", 0, "| x |\n| 1 |")],
    "code": [Context("code", 0, "fix it\n```\nx\n```")],
}


def test_planting_puts_the_instruction_on_its_own_line() -> None:
    assert plant("a\nb", "DO", "start") == "DO\na\nb"
    assert plant("a\nb", "DO", "end") == "a\nb\nDO"
    assert plant("a\nb\nc\nd", "DO", "middle") == "a\nb\nDO\nc\nd"


def test_placements_are_deterministic_and_rotate_positions() -> None:
    chosen = placements(5, 150)
    assert chosen == placements(5, 150)
    assert len(chosen) == CONTEXTS_PER_ATTACK
    assert {position for _, position in chosen} == {"start", "middle", "end"}


def test_text_attacks_go_into_text_contexts_and_code_into_code() -> None:
    docs = build("train", CONTEXTS, [Instruction("text", "c", "T"), Instruction("code", "c", "K")])
    attacks = [d for d in docs if d.label == ATTACK]
    assert {d.task for d in attacks if d.planted == "T"} <= {"email", "table"}
    assert {d.task for d in attacks if d.planted == "K"} == {"code"}
    assert sum(d.label == CLEAN for d in docs) == 3


def test_clean_only_contexts_never_receive_an_attack() -> None:
    extra = [Context("table", 9, "| spare |")]
    docs = build("train", CONTEXTS, [Instruction("text", "c", "T")], clean_only=extra)
    spare = [d for d in docs if "spare" in d.text]
    assert [d.label for d in spare] == [CLEAN]


def test_dump_and_load_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    docs = build("test", CONTEXTS, [Instruction("text", "c", "T")])
    (tmp_path / "documents.jsonl").write_text(dump(docs), encoding="utf-8")
    assert list(load_bipia(tmp_path)) == docs


def test_the_committed_import_has_the_expected_shape() -> None:
    docs = load_bipia()
    counts = Counter((d.split, d.label) for d in docs)
    assert counts == {
        ("train", "attack"): 500,
        ("test", "attack"): 500,
        ("train", "clean"): 989,
        ("test", "clean"): 200,
    }
    for d in docs:
        if d.label == ATTACK:
            assert d.text.count(d.planted) == 1, d.id


def test_the_sealed_manifest_is_exactly_the_test_groups() -> None:
    manifest = load_heldout_manifest(default_bipia_dir() / "heldout.txt")
    assert manifest.ids == {d.group for d in load_bipia() if d.split == "test"}
