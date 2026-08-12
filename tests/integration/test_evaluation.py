"""The harness against the real corpora — and the seal, asserted rather than trusted.

`tests/unit/corpus/test_harness.py` proves the arithmetic on documents small
enough to count by hand. This runs it over the 106 benign documents and the real
attack corpus, where the numbers are whatever the firewall actually does.

Nothing here pins a rate. A test asserting "false positives are 19.8%" would fail
the day somebody improves a detector, which is the wrong incentive entirely — the
corpus tests already fail on a *behaviour* change through the recorded
expectations. What is asserted here is the harness's own contract: that the
false-positive rate is measured over every benign document, that recall and
precision are sliced by different things, that no aggregate exists, and — the one
that matters most — **that the held-out split is not scored by default.**

That last one is a test because ADR 0041's guarantee is otherwise a habit, and a
habit is not something a repository can hold anyone to.
"""

from __future__ import annotations

import pytest

from acp.corpus.harness import DEFAULT_DEPLOYMENT, Report, evaluate_firewall
from acp.corpus.heldout import load_split
from acp.corpus.loader import load_benign
from acp.firewall import Firewall

pytestmark = pytest.mark.integration

RESAMPLES = 300
"""Fewer than the script's 2,000. Nothing asserted here reads an interval bound,
so the extra resamples would buy the suite nothing but seconds."""

NOTICE = "held-out split: NOT SCORED"


@pytest.fixture(scope="module")
def report() -> Report:
    split = load_split()
    firewall = Firewall(enforce=True, allowed_hosts=DEFAULT_DEPLOYMENT.allowed_hosts)
    return evaluate_firewall(
        firewall,
        benign=load_benign(),
        attacks=split.development,
        heldout_notice=NOTICE,
        detectors=("deterministic patterns",),
        resamples=RESAMPLES,
    )


# ---------------------------------------------------------------------------
# The seal
# ---------------------------------------------------------------------------


def test_the_default_run_does_not_score_the_held_out_split(report: Report) -> None:
    """**ADR 0041, enforced rather than promised.**

    The split's whole value is that nothing in it has influenced a detector. A
    harness that scored it by default would be read by default, and by the third
    "that moved, let me try something" it has become a second development set.
    Scoring it takes a deliberate flag; this asserts the default stayed default.
    """
    assert not report.scored_heldout
    assert report.heldout_notice == NOTICE


def test_the_development_split_excludes_every_held_out_attack() -> None:
    """The seal from the other side: not just unscored, but absent from the
    corpus the harness was handed."""
    split = load_split()

    development = {attack.id for attack in split.development.attacks}
    heldout = {attack.id for attack in split.heldout.attacks}

    assert development.isdisjoint(heldout)
    assert heldout


def test_the_report_names_the_split_on_every_run(report: Report) -> None:
    """Visible in the artifact, not asserted in a document nobody opens."""
    assert report.heldout_notice


# ---------------------------------------------------------------------------
# What is measured, and over what
# ---------------------------------------------------------------------------


def test_the_false_positive_rate_covers_every_benign_document(report: Report) -> None:
    """No sampling and no exclusions. A false-positive rate over a filtered
    corpus is a rate over whatever survived the filter."""
    assert report.false_positive_rate.total == len(load_benign())


def test_withholding_a_benign_document_is_measured_separately(report: Report) -> None:
    """Flagged and stopped are different events, and only one of them gets a
    security control switched off. As of task 48's demotion the second is zero,
    which is the claim the ADR makes and this is where it is checked."""
    assert report.benign_withheld_rate.total == report.false_positive_rate.total
    assert report.benign_withheld_rate.successes <= report.false_positive_rate.successes


def test_every_attack_family_gets_a_recall_row(report: Report) -> None:
    split = load_split()

    assert {row.family for row in report.recall} == set(split.development.families)


def test_recall_and_precision_are_sliced_by_different_things(report: Report) -> None:
    """The two tables are indexed by two different enums — `AttackFamily`, which
    the corpus assigns, and `Family`, which a detector reports. `AttackFamily` is
    a superset, so a row type that could hold either would let the two be
    conflated without a type error."""
    recall_families = {row.family.value for row in report.recall}
    precision_families = {row.family.value for row in report.precision}

    assert recall_families - precision_families, (
        "every attack family is also a reported family — the slicing distinction "
        "is untested by this corpus"
    )


def test_there_is_no_aggregate_detection_rate(report: Report) -> None:
    """ADR 0036, made structural. An average over families that include
    `plain_assertion` (nothing catches it, by construction) is a number set by
    how many of each somebody wrote."""
    assert not hasattr(report, "catch_rate")
    assert not hasattr(report, "detection_rate")


def test_precision_counts_benign_documents_in_its_denominator(report: Report) -> None:
    """Precision over attacks alone is structurally 100%. If no reported family
    ever hits a benign document, this harness is measuring nothing."""
    assert any(row.benign_hits for row in report.precision)


# ---------------------------------------------------------------------------
# Honesty about the numbers
# ---------------------------------------------------------------------------


def test_a_small_family_is_flagged_as_too_small_to_quote(report: Report) -> None:
    """Every family in this corpus is under ten documents. The harness says so
    rather than leaving a reader to check seven denominators."""
    assert report.warnings
    assert any("read the interval" in warning for warning in report.warnings)


def test_a_family_nothing_catches_gets_an_uninformative_interval(report: Report) -> None:
    """`plain_assertion` is 0 for 6 — a unanimous sample, where the percentile
    bootstrap can only return a point. Marked uninformative rather than printed
    as a tight interval around zero."""
    row = next(row for row in report.recall if row.family.value == "plain_assertion")

    assert row.detected.successes == 0
    assert row.detected.interval.degenerate
    assert row.detected.interval.render() == "[uninformative]"


def test_the_report_states_its_own_configuration(report: Report) -> None:
    """`disallowed_url` and `tool_name_mention` are entirely a function of the
    allow-list and the catalogue, so a rate quoted without them cannot be
    reproduced or disputed."""
    assert report.deployment
    assert report.detectors
    assert report.seed


def test_every_attack_still_does_what_the_corpus_records(report: Report) -> None:
    """The regression assertion, and the reason `make eval` has an exit code.

    A mismatch in either direction is a behaviour change — a firewall that starts
    catching something new is an improvement and still something somebody has to
    acknowledge in the corpus and the ADR.
    """
    assert report.matched, f"expectation mismatches: {report.all_mismatches}"
