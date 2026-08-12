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

from acp.corpus import AttackCorpus, Expectation, load_attacks
from acp.corpus.attack import AttackFamily
from acp.corpus.evaluate import evaluate, outcome_of
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
    return load_attacks()


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
