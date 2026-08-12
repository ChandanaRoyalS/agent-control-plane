"""The adversarial-corpus parser, and the taxonomy it enforces.

Same strictness as the benign parser, over a different set of keys, and one
extra invariant that matters more than any of them: the attack families must be
a *superset* of the detector families, so a per-family detection rate can be
computed by comparing the two directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.corpus.attack import AttackFamily, Expectation, parse_attack
from acp.corpus.document import Source
from acp.corpus.loader import load_attacks
from acp.exceptions import ConfigurationError
from acp.firewall.findings import Family

FRONT = "---\nwhy: it is here for a reason\nsource: synthetic\nexpect: detected\n---\n"


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_every_detector_family_is_an_attack_family() -> None:
    """The invariant the whole taxonomy rests on.

    `AttackFamily` is deliberately a superset of `firewall.findings.Family`: the
    families a detector can report, spelled identically so the two can be
    compared directly, plus the families no detector can. If a detector family
    had no attack-family counterpart, its detection rate would be uncomputable.
    """
    detector_families = {family.value for family in Family}
    attack_families = {family.value for family in AttackFamily}

    assert detector_families <= attack_families


def test_the_extra_families_are_the_uncatchable_ones() -> None:
    """And they are named, not smuggled in. The two attack families with no
    detector are the point of ADR 0040 — a taxonomy that only contains what you
    can catch is one that flatters you."""
    extra = {family.value for family in AttackFamily} - {family.value for family in Family}

    assert extra == {"plain_assertion", "delayed_multi_step"}


def test_an_attack_parses_into_family_expectation_and_text(tmp_path: Path) -> None:
    path = write(tmp_path, "example.txt", FRONT + "the attack itself\n")

    attack = parse_attack(path, path.read_text(encoding="utf-8"), family="direct_override")

    assert attack.id == "direct_override/example"
    assert attack.family is AttackFamily.DIRECT_OVERRIDE
    assert attack.expect is Expectation.DETECTED
    assert attack.source is Source.SYNTHETIC
    assert attack.text == "the attack itself"


def test_the_family_comes_from_the_directory_not_a_field(tmp_path: Path) -> None:
    """A file that could name a family different from the directory it sits in is
    a file that eventually does, and the slice is the whole point."""
    path = write(tmp_path, "x.txt", FRONT + "body\n")

    attack = parse_attack(path, path.read_text(encoding="utf-8"), family="exfiltration")

    assert attack.family is AttackFamily.EXFILTRATION


def test_a_directory_that_is_not_a_family_is_refused(tmp_path: Path) -> None:
    path = write(tmp_path, "x.txt", FRONT + "body\n")

    with pytest.raises(ConfigurationError, match="not an attack family"):
        parse_attack(path, path.read_text(encoding="utf-8"), family="nonsense")


def test_a_missing_expectation_is_refused(tmp_path: Path) -> None:
    """`expect` is required here where the benign corpus has no such field: an
    attack with no stated expectation is one the harness cannot score."""
    text = "---\nwhy: x\nsource: synthetic\n---\nbody\n"
    path = write(tmp_path, "x.txt", text)

    with pytest.raises(ConfigurationError, match="expect"):
        parse_attack(path, text, family="direct_override")


def test_an_unknown_expectation_is_refused(tmp_path: Path) -> None:
    text = "---\nwhy: x\nsource: synthetic\nexpect: blocked\n---\nbody\n"
    path = write(tmp_path, "x.txt", text)

    with pytest.raises(ConfigurationError, match="expect"):
        parse_attack(path, text, family="direct_override")


def test_the_hard_key_is_not_understood_here(tmp_path: Path) -> None:
    """The benign corpus's `hard` has no meaning for an attack, and the shared
    strict parser must reject it rather than ignore it — otherwise the two
    corpora's schemas quietly drift."""
    text = "---\nwhy: x\nsource: synthetic\nexpect: detected\nhard: true\n---\nbody\n"
    path = write(tmp_path, "x.txt", text)

    with pytest.raises(ConfigurationError, match="nobody reads"):
        parse_attack(path, text, family="direct_override")


# ---------------------------------------------------------------------------
# Loading the directory
# ---------------------------------------------------------------------------


def test_a_family_directory_loads(tmp_path: Path) -> None:
    write(tmp_path / "attack" / "direct_override", "a.txt", FRONT + "one\n")
    write(tmp_path / "attack" / "obfuscation", "b.txt", FRONT + "two\n")

    corpus = load_attacks(tmp_path)

    assert len(corpus) == 2
    assert corpus.families == (AttackFamily.DIRECT_OVERRIDE, AttackFamily.OBFUSCATION)


def test_an_empty_family_is_refused(tmp_path: Path) -> None:
    (tmp_path / "attack" / "direct_override").mkdir(parents=True)

    with pytest.raises(ConfigurationError, match="no documents"):
        load_attacks(tmp_path)


def test_a_missing_attack_corpus_says_where_it_lives(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not packaged"):
        load_attacks(tmp_path)


def test_undetectable_is_the_expecting_undetected_slice(tmp_path: Path) -> None:
    undetected_front = FRONT.replace("detected", "undetected")
    write(tmp_path / "attack" / "plain_assertion", "a.txt", undetected_front + "x\n")
    write(tmp_path / "attack" / "direct_override", "b.txt", FRONT + "y\n")

    corpus = load_attacks(tmp_path)

    assert {a.id for a in corpus.undetectable} == {"plain_assertion/a"}
