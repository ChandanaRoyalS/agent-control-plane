"""The adversarial corpus against the live firewall — task 49.

The benign corpus (task 48) asserts a floor: nothing benign is withheld. This
asserts the other half, and it asserts it in a way that is easy to get wrong.

The naive version checks a detection rate against a threshold. That number is a
property of the corpus — write more `plain_assertion` attacks and it falls,
write more `obfuscation` and it rises — so a threshold on it measures the author,
not the firewall. Instead, every attack carries what the firewall is *expected*
to do with it, and the test asserts the firewall does exactly that. A drift in
either direction fails: an attack that stops being caught is a regression, and an
attack that starts being caught is a behaviour change that has to be
acknowledged rather than absorbed.
"""

from __future__ import annotations

import logging

import pytest

from acp.corpus import AttackCorpus, Expectation
from acp.corpus.attack import AttackFamily
from acp.corpus.evaluate import evaluate, outcome_of
from acp.corpus.heldout import (
    Split,
    load_development_attacks,
    load_split,
    unsealed_ids,
    verify_seal,
)
from acp.firewall import Firewall
from acp.firewall.findings import Family

pytestmark = pytest.mark.integration

MIN_ATTACKS = 40
MIN_FAMILIES = 7
MIN_PER_FAMILY = 4

ALLOWED_HOSTS = frozenset({"docs.corp", "cdn.corp", "acme.example"})
"""A configured deployment, so `external_image` and `disallowed_url` behave as a
real one would — reporting a URL that points somewhere other than these."""

CATALOGUE = frozenset(
    {
        "mock-a__search",
        "mock-a__create_ticket",
        "mock-b__delete_record",
        "mock-b__summarize",
    }
)
"""A catalogue whose names the tool-confusion attacks deliberately mention, so
that detector can fire. The fair test, not the flattering one."""


@pytest.fixture(scope="module")
def attacks() -> AttackCorpus:
    """**The development split only** — the held-out set is not scored here.

    This fixture used to be `load_attacks()`, so every CI run scored all seven
    held-out documents against their recorded expectations. A set that is
    measured on every commit is not held out; it is development data with a
    ceremony attached, and the generalisation number it produces is the number
    it was tuned to produce (ADR 0064).

    `load_development_attacks` is the loader `heldout.py` wrote for exactly this
    and which nothing called. Scoring the sealed split is `evaluate.py
    --unseal`, deliberately explicit and deliberately rare.
    """
    return load_development_attacks()


@pytest.fixture(scope="module")
def split() -> Split:
    return load_split()


@pytest.fixture(scope="module")
def firewall() -> Firewall:
    return Firewall(enforce=True, allowed_hosts=ALLOWED_HOSTS)


class silent:  # noqa: N801 — context manager used as a verb
    def __enter__(self) -> None:
        logging.disable(logging.CRITICAL)

    def __exit__(self, *_: object) -> None:
        logging.disable(logging.NOTSET)


# ---------------------------------------------------------------------------
# The expectations hold
# ---------------------------------------------------------------------------


def test_every_attack_does_what_the_corpus_expects(
    attacks: AttackCorpus, firewall: Firewall
) -> None:
    """The load-bearing assertion, and it fails in both directions.

    An attack expected `withheld` that is no longer withheld is a regression.
    An attack expected `undetected` that now produces a finding is a genuine
    improvement — and it still fails, deliberately, because a security control
    changing what it catches without anybody noticing is the thing this project
    spends its effort preventing. The fix is one line of front matter and a
    sentence in ADR 0040, which is exactly the review that should happen.
    """
    with silent():
        board = evaluate(firewall, attacks.attacks, tools=CATALOGUE)

    assert board.matched, f"expectation drift: {', '.join(board.all_mismatches)}"


def test_the_obfuscation_family_is_where_enforcement_lives(
    attacks: AttackCorpus, firewall: Firewall
) -> None:
    """After ADR 0039 demoted the tool-mention and image detectors, the only
    attacks that can be *withheld* are obfuscation ones — a bidirectional
    override or a decoded instruction. Asserting it here keeps that fact visible
    rather than buried in the enforceable set."""
    with silent():
        board = evaluate(firewall, attacks.attacks, tools=CATALOGUE)

    withheld_families = {row.family for row in board.rows if row.withheld}

    assert withheld_families == {AttackFamily.OBFUSCATION}


def test_the_uncatchable_families_are_genuinely_uncatchable(
    attacks: AttackCorpus, firewall: Firewall
) -> None:
    """`plain_assertion` and `delayed_multi_step` produce no finding at all, and
    that is asserted rather than assumed. If a pattern ever fires on one of
    these, it is almost certainly a false-positive shape that would fire on
    honest prose too, and the build should stop so somebody looks."""
    uncatchable = {AttackFamily.PLAIN_ASSERTION, AttackFamily.DELAYED_MULTI_STEP}

    with silent():
        for attack in attacks.attacks:
            if attack.family in uncatchable:
                actual = outcome_of(firewall, attack.text, tools=CATALOGUE)
                assert actual is Expectation.UNDETECTED, attack.id


def test_the_direct_override_family_is_detected_never_withheld(
    attacks: AttackCorpus, firewall: Firewall
) -> None:
    """The famous family, and the one ADR 0036 caps at MEDIUM so it can never
    withhold — because writing *about* the attack uses the same sentences. A
    detected-not-withheld outcome here is the design, not a shortfall."""
    with silent():
        for attack in attacks.of_family(AttackFamily.DIRECT_OVERRIDE):
            actual = outcome_of(firewall, attack.text, tools=CATALOGUE)
            assert actual is not Expectation.WITHHELD, attack.id


# ---------------------------------------------------------------------------
# The corpus is broad enough to mean something
# ---------------------------------------------------------------------------


def test_the_corpus_covers_every_family(attacks: AttackCorpus) -> None:
    assert len(attacks.families) >= MIN_FAMILIES


def test_every_detector_family_has_attacks(attacks: AttackCorpus) -> None:
    """A detector family with no attacks is a detector nothing exercises. Every
    `Family` a detector can report must appear in the corpus."""
    present = {family.value for family in attacks.families}
    for family in Family:
        assert family.value in present, family.value


def test_every_family_has_several_attacks(attacks: AttackCorpus) -> None:
    """A family with one attack is a slice whose rate is 0% or 100%."""
    thin = [f.value for f in attacks.families if len(attacks.of_family(f)) < MIN_PER_FAMILY]
    assert thin == []


def test_the_corpus_is_large_enough(attacks: AttackCorpus) -> None:
    assert len(attacks) >= MIN_ATTACKS


def test_a_real_share_of_attacks_are_uncatchable_by_design(attacks: AttackCorpus) -> None:
    """The honesty check, mirrored from the benign corpus's anti-filler test.

    A corpus of only catchable attacks reports a catch rate that is a property of
    the corpus. If the uncatchable slice ever shrinks to nothing, the corpus has
    quietly become a list of the firewall's greatest hits.
    """
    assert len(attacks.undetectable) >= 10


def test_every_attack_says_why_it_is_here(attacks: AttackCorpus) -> None:
    assert all(attack.why for attack in attacks.attacks)


# ---------------------------------------------------------------------------
# The scoreboard refuses to lie
# ---------------------------------------------------------------------------


def test_the_scoreboard_reports_per_family_not_an_aggregate(
    attacks: AttackCorpus, firewall: Firewall
) -> None:
    """There is deliberately no single catch rate. An aggregate over families
    that includes the uncatchable ones is a number whose value depends on how
    many of each were written — so `Scoreboard` exposes rows and no total."""
    with silent():
        board = evaluate(firewall, attacks.attacks, tools=CATALOGUE)

    assert not hasattr(board, "catch_rate")
    assert {row.family for row in board.rows} == set(attacks.families)
    assert all(0.0 <= row.catch_rate <= 1.0 for row in board.rows)


# ---------------------------------------------------------------------------
# The seal
# ---------------------------------------------------------------------------


def test_every_held_out_document_still_matches_its_seal(split: Split) -> None:
    """**What turns a list of ids into a held-out set.**

    Without a digest, "held out" is a promise that these files were not read
    while tuning — a promise nothing checks, and one that editing a file
    quietly breaks. The seal covers the payload *and* its expectation, because
    changing `expect: detected` to `expect: undetected` after a disappointing
    run is the tampering worth catching.
    """
    assert verify_seal(split.heldout, split.manifest) == ()


def test_every_held_out_document_is_sealed(split: Split) -> None:
    """An unsealed entry is a weaker claim, not an equivalent one, so it is
    named rather than allowed to pass as sealed."""
    assert unsealed_ids(split.manifest) == ()


def test_the_held_out_split_is_not_scored_by_the_routine_suite(split: Split) -> None:
    """The property the `attacks` fixture change protects, asserted rather than
    left to a reader noticing which loader was called."""
    development = {attack.id for attack in load_development_attacks().attacks}
    held_out = {attack.id for attack in split.heldout.attacks}

    assert held_out
    assert development.isdisjoint(held_out)
