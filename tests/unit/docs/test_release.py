"""The release: one version string, one changelog, and both agreeing.

Task 67. A version lives in two files because packaging needs it in
`pyproject.toml` and the code needs it importable, and two sources of truth for
one fact is a disagreement waiting for a release. So they are checked against
each other, and both against the changelog.

The parsing under test is `acp.changelog`, which is pure. These tests are what
turns a hand-written changelog from a document that might be current into one
that cannot be stale about the version being tagged.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from acp import __version__
from acp.changelog import UNRELEASED, notes, order, parse

ROOT = Path(__file__).resolve().parents[3]
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"

MINIMUM_NOTE_LENGTH = 50


@pytest.fixture(scope="module")
def changelog() -> str:
    return CHANGELOG.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# One version, in two files
# ---------------------------------------------------------------------------


def test_pyproject_and_the_package_agree_on_the_version() -> None:
    """The failure this prevents is a wheel whose metadata says 1.0.0 and whose
    `--version` says 0.9.0, which is only ever noticed by whoever is trying to
    reproduce a bug."""
    packaged = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert packaged == __version__


def test_the_version_is_a_semantic_version() -> None:
    assert order(__version__)


# ---------------------------------------------------------------------------
# The changelog
# ---------------------------------------------------------------------------


def test_the_changelog_has_sections(changelog: str) -> None:
    """LESSON 65 — the premise, before anything that depends on it.

    Every test below would pass vacuously against a changelog whose headings
    stopped matching the pattern.
    """
    assert len(parse(changelog)) >= 1


def test_the_changelog_describes_the_current_version(changelog: str) -> None:
    """A release tagged without notes is indistinguishable from one whose notes
    were lost, and the release workflow refuses rather than guessing."""
    body = notes(changelog, __version__)
    assert body is not None, f"CHANGELOG.md has no section for {__version__}"
    assert len(body) >= MINIMUM_NOTE_LENGTH


def test_every_released_section_carries_a_date(changelog: str) -> None:
    for release in parse(changelog):
        if release.released:
            assert release.date, f"{release.version} has no date"


def test_the_unreleased_section_comes_first_if_it_exists(changelog: str) -> None:
    """Below a released version it would read as part of that release's notes,
    which is the one place a reader must not be misled."""
    sections = parse(changelog)
    unreleased = [i for i, release in enumerate(sections) if not release.released]
    assert unreleased in ([], [0])


def test_the_versions_descend(changelog: str) -> None:
    """Newest first, which is the order a person reads a changelog in — and
    `order()` raising on anything that is not three integers makes this also a
    test that every heading is a real version."""
    released = [order(r.version) for r in parse(changelog) if r.released]
    assert released == sorted(released, reverse=True)


def test_no_version_appears_twice(changelog: str) -> None:
    versions = [release.version for release in parse(changelog)]
    assert len(versions) == len(set(versions))


# ---------------------------------------------------------------------------
# The parser itself
# ---------------------------------------------------------------------------


def test_a_section_is_read_from_its_heading_to_the_next() -> None:
    text = "\n".join(
        [
            "# Changelog",
            "",
            "## [Unreleased]",
            "",
            "pending",
            "",
            "## [1.0.0] - 2026-08-14",
            "",
            "the first one",
            "",
            "## [0.9.0] - 2026-01-01",
            "",
            "older",
        ]
    )
    sections = parse(text)

    assert [r.version for r in sections] == [UNRELEASED, "1.0.0", "0.9.0"]
    assert sections[0].date is None
    assert sections[1].date == "2026-08-14"
    assert sections[1].body == "the first one"


def test_a_line_that_merely_contains_brackets_is_not_a_heading() -> None:
    """Anchored at both ends, because prose citing `## [1.0.0]` mid-sentence
    would otherwise split a release's notes in half and the shorter half would
    be published."""
    text = "## [1.0.0] - 2026-08-14\n\nsee also ## [0.9.0] - 2026-01-01 for the old shape\n"
    sections = parse(text)

    assert len(sections) == 1
    assert "0.9.0" in sections[0].body


def test_notes_for_an_unknown_version_are_none() -> None:
    assert notes("## [1.0.0] - 2026-08-14\n\nbody\n", "2.0.0") is None


def test_notes_for_an_empty_section_are_none() -> None:
    """An empty body and a missing section are the same failure to a reader, so
    they are the same answer here."""
    assert notes("## [1.0.0] - 2026-08-14\n\n", "1.0.0") is None


def test_a_heading_that_is_not_a_version_is_rejected_by_order() -> None:
    with pytest.raises(ValueError, match="not a semantic version"):
        order("1.0")
