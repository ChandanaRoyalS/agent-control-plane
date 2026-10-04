"""The held-out split: parsed, partitioned, and proven sealed.

The load-bearing tests here are the ones that fail when the split is emptied or
leaks — a split whose tests pass because it holds nothing out is worse than no
split, because it reports a generalisation number measured against training data.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.corpus import (
    load_attacks,
    load_development_attacks,
    load_heldout_manifest,
    load_split,
    split_attacks,
)
from acp.corpus.heldout import HeldoutManifest, default_heldout_path
from acp.exceptions import ConfigurationError


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "heldout.txt"
    path.write_text(text, encoding="utf-8")
    return path


# -- manifest parsing --------------------------------------------------------


def test_parses_version_and_ids(tmp_path: Path) -> None:
    path = _write(tmp_path, "version: 3\n\n# a comment\nfoo/bar\nbaz/qux\n")
    manifest = load_heldout_manifest(path)
    assert manifest.version == 3
    assert manifest.ids == frozenset({"foo/bar", "baz/qux"})


def test_a_missing_version_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, "foo/bar\n")
    with pytest.raises(ConfigurationError, match="has no"):
        load_heldout_manifest(path)


def test_a_non_integer_version_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, "version: one\nfoo/bar\n")
    with pytest.raises(ConfigurationError, match="version must be an integer"):
        load_heldout_manifest(path)


def test_an_empty_manifest_is_rejected(tmp_path: Path) -> None:
    """A manifest that holds nothing out is a measurement against nothing."""
    path = _write(tmp_path, "version: 1\n")
    with pytest.raises(ConfigurationError, match="holds nothing out"):
        load_heldout_manifest(path)


def test_a_bare_word_is_not_an_id(tmp_path: Path) -> None:
    path = _write(tmp_path, "version: 1\nnotanid\n")
    with pytest.raises(ConfigurationError, match=r"not an attack id"):
        load_heldout_manifest(path)


def test_a_duplicate_id_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, "version: 1\nfoo/bar\nfoo/bar\n")
    with pytest.raises(ConfigurationError, match="duplicate id"):
        load_heldout_manifest(path)


def test_a_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="cannot read held-out manifest"):
        load_heldout_manifest(tmp_path / "nope.txt")


# -- partition ---------------------------------------------------------------


def test_split_partitions_on_the_manifest() -> None:
    corpus = load_attacks()
    manifest = load_heldout_manifest(default_heldout_path())
    split = split_attacks(corpus, manifest)

    dev_ids = {a.id for a in split.development.attacks}
    held_ids = {a.id for a in split.heldout.attacks}
    assert dev_ids.isdisjoint(held_ids)
    assert dev_ids | held_ids == {a.id for a in corpus.attacks}
    assert held_ids == set(manifest.ids)


def test_a_manifest_id_absent_from_the_corpus_is_an_error() -> None:
    corpus = load_attacks()
    manifest = HeldoutManifest(version=1, ids=frozenset({"direct_override/no-such-attack"}))
    with pytest.raises(ConfigurationError, match="not in the corpus"):
        split_attacks(corpus, manifest)


# -- the seal, and the anti-filler assertions ------------------------------


def test_the_development_loader_excludes_every_held_out_id() -> None:
    """The property the whole task exists for: nothing a detector is tuned
    against is in the held-out set."""
    development = load_development_attacks()
    manifest = load_heldout_manifest(default_heldout_path())
    dev_ids = {a.id for a in development.attacks}
    assert dev_ids.isdisjoint(manifest.ids)


def test_the_held_out_split_is_not_empty() -> None:
    """Fails if the manifest is emptied — the test that stops the seal being
    made to pass by holding nothing out."""
    assert len(load_split().heldout) > 0


def test_every_family_is_represented_in_the_held_out_split() -> None:
    """Fails if a family is dropped from the manifest. A held-out set missing a
    family cannot measure generalisation for it, so an aggregate over the rest
    would silently exclude it — the split has to cover what it claims to test."""
    split = load_split()
    held_families = {a.family for a in split.heldout.attacks}
    all_families = {a.family for a in load_attacks().attacks}
    assert held_families == all_families


def test_development_and_heldout_together_lose_nothing() -> None:
    """The split partitions; it does not drop. Every attack lands on exactly one
    side, so no document quietly vanishes from both the tuning and the test set."""
    split = load_split()
    total = len(split.development) + len(split.heldout)
    assert total == len(load_attacks())


# -- a split is unseen exactly once -----------------------------------------


def test_an_unsealed_line_is_parsed_and_carried_into_the_split(tmp_path: Path) -> None:
    path = _write(tmp_path, "version: 2\nunsealed: 2027-01-01, ADR 0099\nfoo/bar\n")
    manifest = load_heldout_manifest(path)
    assert manifest.unsealed == "2027-01-01, ADR 0099"


def test_a_manifest_without_the_line_is_still_sealed(tmp_path: Path) -> None:
    assert load_heldout_manifest(_write(tmp_path, "version: 1\nfoo/bar\n")).unsealed is None


def test_an_empty_unsealed_line_is_rejected(tmp_path: Path) -> None:
    """A bare `unsealed:` records that the seal broke without saying where the
    number went — the one piece of information the line exists to carry."""
    with pytest.raises(ConfigurationError, match="needs a date and a reference"):
        load_heldout_manifest(_write(tmp_path, "version: 1\nunsealed:\nfoo/bar\n"))


def test_the_committed_v1_split_records_that_it_was_unsealed() -> None:
    """v1 was scored once (ADR 0060). Removing the line would let the next run
    present those seven attacks as unseen again — the exact claim the split can
    no longer support."""
    split = load_split()
    if split.version == 1:
        assert split.unsealed is not None
        assert "ADR 0060" in split.unsealed
