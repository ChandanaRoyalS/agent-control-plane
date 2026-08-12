"""The corpus parser, which is strict on purpose.

A corpus is edited by hand over months. Every failure mode here is one where a
document quietly leaves the set the numbers are computed from — and a
false-positive rate over a silently smaller denominator is wrong in the
direction nobody checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.corpus.document import Source, parse
from acp.corpus.loader import load_corpus, repository_root
from acp.exceptions import ConfigurationError

FRONT = "---\nwhy: it is here for a reason\nsource: synthetic\n---\n"


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_a_document_parses_into_its_metadata_and_its_text(tmp_path: Path) -> None:
    path = write(tmp_path, "example.txt", FRONT + "the body of the document\n")

    document = parse(path, path.read_text(encoding="utf-8"), kind="doc")

    assert document.id == "doc/example"
    assert document.kind == "doc"
    assert document.why == "it is here for a reason"
    assert document.source is Source.SYNTHETIC
    assert document.hard is False
    assert document.text == "the body of the document"


def test_the_body_is_kept_byte_for_byte(tmp_path: Path) -> None:
    """The reason front matter is fenced rather than encoded.

    Several documents carry zero-width joiners and directional marks on purpose.
    A format that escaped them would store a description of the document instead
    of the document, and the corpus would stop testing the thing it exists for.
    """
    body = "family \U0001f468\u200d\U0001f469\u200d\U0001f467 and \u200fmixed\u200f text"
    path = write(tmp_path, "unicode.txt", FRONT + body + "\n")

    assert parse(path, path.read_text(encoding="utf-8"), kind="i18n").text == body


def test_hard_is_recorded_when_present(tmp_path: Path) -> None:
    text = "---\nwhy: quotes a payload\nsource: synthetic\nhard: true\n---\nbody\n"
    path = write(tmp_path, "hard.txt", text)

    assert parse(path, text, kind="advisory").hard is True


def test_a_file_with_no_front_matter_is_refused(tmp_path: Path) -> None:
    path = write(tmp_path, "bare.txt", "just a document\n")

    with pytest.raises(ConfigurationError, match="front matter"):
        parse(path, path.read_text(encoding="utf-8"), kind="doc")


def test_an_unclosed_front_matter_block_is_refused(tmp_path: Path) -> None:
    path = write(tmp_path, "unclosed.txt", "---\nwhy: x\nsource: synthetic\nbody\n")

    with pytest.raises(ConfigurationError, match="closing"):
        parse(path, path.read_text(encoding="utf-8"), kind="doc")


def test_missing_metadata_is_refused_by_name(tmp_path: Path) -> None:
    path = write(tmp_path, "nosource.txt", "---\nwhy: x\n---\nbody\n")

    with pytest.raises(ConfigurationError, match="source"):
        parse(path, path.read_text(encoding="utf-8"), kind="doc")


def test_an_unknown_key_is_refused(tmp_path: Path) -> None:
    """The typo case, and the reason this parser is strict.

    `hardd: true` that silently means "not hard" is a near-miss quietly leaving
    the slice the numbers are drawn from, and nothing anywhere would say so.
    """
    text = "---\nwhy: x\nsource: synthetic\nhardd: true\n---\nbody\n"
    path = write(tmp_path, "typo.txt", text)

    with pytest.raises(ConfigurationError, match="nobody reads"):
        parse(path, text, kind="doc")


def test_an_unknown_source_is_refused(tmp_path: Path) -> None:
    text = "---\nwhy: x\nsource: imagined\n---\nbody\n"
    path = write(tmp_path, "badsource.txt", text)

    with pytest.raises(ConfigurationError, match="source"):
        parse(path, text, kind="doc")


def test_an_empty_why_is_refused(tmp_path: Path) -> None:
    text = '---\nwhy: ""\nsource: synthetic\n---\nbody\n'
    path = write(tmp_path, "nowhy.txt", text)

    with pytest.raises(ConfigurationError, match="why"):
        parse(path, text, kind="doc")


def test_a_document_with_no_body_is_refused(tmp_path: Path) -> None:
    path = write(tmp_path, "empty.txt", FRONT + "\n\n")

    with pytest.raises(ConfigurationError, match="no document"):
        parse(path, path.read_text(encoding="utf-8"), kind="doc")


def test_invalid_front_matter_is_refused(tmp_path: Path) -> None:
    text = "---\nwhy: [unclosed\nsource: synthetic\n---\nbody\n"
    path = write(tmp_path, "badyaml.txt", text)

    with pytest.raises(ConfigurationError, match="front matter"):
        parse(path, text, kind="doc")


def test_front_matter_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    text = "---\n- why\n- source\n---\nbody\n"
    path = write(tmp_path, "list.txt", text)

    with pytest.raises(ConfigurationError, match="mapping"):
        parse(path, text, kind="doc")


# ---------------------------------------------------------------------------
# Loading a directory
# ---------------------------------------------------------------------------


def test_a_directory_loads_every_kind(tmp_path: Path) -> None:
    write(tmp_path / "doc", "a.txt", FRONT + "one\n")
    write(tmp_path / "doc", "b.txt", FRONT + "two\n")
    write(tmp_path / "log", "c.txt", FRONT + "three\n")

    corpus = load_corpus(tmp_path)

    assert len(corpus) == 3
    assert corpus.kinds == ("doc", "log")
    assert {d.id for d in corpus.of_kind("doc")} == {"doc/a", "doc/b"}


def test_a_missing_directory_says_where_the_corpus_lives(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not packaged"):
        load_corpus(tmp_path / "nothing-here")


def test_a_directory_with_no_kinds_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="no kind subdirectories"):
        load_corpus(tmp_path)


def test_an_empty_kind_is_refused(tmp_path: Path) -> None:
    """A slice the harness would report a rate for, computed from nothing."""
    (tmp_path / "doc").mkdir()

    with pytest.raises(ConfigurationError, match="no documents"):
        load_corpus(tmp_path)


def test_one_malformed_file_stops_the_whole_load(tmp_path: Path) -> None:
    """Rather than being skipped. A corpus that loads 94 of 97 documents still
    produces a number, and the number is wrong over a denominator nobody
    checked."""
    write(tmp_path / "doc", "good.txt", FRONT + "fine\n")
    write(tmp_path / "doc", "bad.txt", "no front matter here\n")

    with pytest.raises(ConfigurationError, match=r"bad\.txt"):
        load_corpus(tmp_path)


def test_the_repository_root_is_found_rather_than_counted() -> None:
    """`parents[3]` would work today and break silently the first time this
    module moves, by resolving to a directory that happens to exist."""
    assert (repository_root() / "pyproject.toml").is_file()


def test_no_root_above_a_temporary_directory(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"pyproject\.toml"):
        repository_root(tmp_path / "deep" / "nested" / "file.py")
