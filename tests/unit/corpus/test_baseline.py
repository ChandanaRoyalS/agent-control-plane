"""The regression gate: a diff against a committed baseline, not a threshold.

Three outcomes are being asserted, and the third is the one a simpler design
would get wrong. A comparison can find a regression, an improvement, or a
*structural* change where the two runs are not comparable at all — the corpus
grew, a family appeared, the deployment moved. Calling that third case a
regression sends somebody hunting a bug in the firewall that is really a document
they added.

The asymmetry is the other half. Detection falling is a regression; detection
rising is not. False positives rising is a regression; falling is not. Every
count in the baseline has a direction, and a gate that treated any change as a
failure would be a gate people disable the first time they improve something.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.corpus.attack import AttackFamily, Expectation
from acp.corpus.baseline import (
    BASELINE_VERSION,
    Baseline,
    FamilyCounts,
    ReportedCounts,
    baseline_from,
    compare,
    load_baseline,
)
from acp.corpus.harness import Report
from acp.exceptions import ConfigurationError

from .test_harness import CLEAN, EXFIL, WITHHELD, attacks, benign, report


def a_report() -> Report:
    """A run with one flagged benign document and one caught attack."""
    return report(
        benign(CLEAN, EXFIL),
        attacks((AttackFamily.EXFILTRATION, Expectation.DETECTED, EXFIL)),
    )


def a_baseline(
    *,
    deployment: str | None = None,
    detectors: tuple[str, ...] | None = None,
    benign_total: int | None = None,
    benign_flagged: int | None = None,
    benign_withheld: int | None = None,
    families: dict[str, FamilyCounts] | None = None,
    reported: dict[str, ReportedCounts] | None = None,
) -> Baseline:
    """The baseline this run would produce, with named fields overridden.

    Every parameter spelled out rather than taken as ``**overrides: object``.
    That shortcut typechecks as `Any` in the sandbox and fails `mypy --strict`
    on a machine that can resolve the model — the same trap as bug 42, and the
    reason this project does not splat loose mappings into typed constructors.
    """
    base = baseline_from(a_report())
    return Baseline(
        version=base.version,
        deployment=base.deployment if deployment is None else deployment,
        detectors=base.detectors if detectors is None else detectors,
        benign_total=base.benign_total if benign_total is None else benign_total,
        benign_flagged=base.benign_flagged if benign_flagged is None else benign_flagged,
        benign_withheld=base.benign_withheld if benign_withheld is None else benign_withheld,
        families=base.families if families is None else families,
        reported=base.reported if reported is None else reported,
    )


# ---------------------------------------------------------------------------
# Capturing
# ---------------------------------------------------------------------------


def test_a_baseline_records_counts_not_rates() -> None:
    """A rate hides its own denominator: 19.8% and 20.7% look like drift and are
    one document out of 106. Counts make the corpus size part of the
    comparison."""
    baseline = baseline_from(a_report())

    assert baseline.benign_total == 2
    assert baseline.benign_flagged == 1
    assert baseline.families["exfiltration"].detected == 1


def test_a_baseline_round_trips_through_its_own_json(tmp_path: Path) -> None:
    original = baseline_from(a_report())
    path = tmp_path / "eval-baseline.json"
    path.write_text(original.to_json(), encoding="utf-8")

    assert load_baseline(path) == original


def test_the_json_is_written_for_a_human_reading_a_diff() -> None:
    """Sorted and indented, so a change to one number is a one-line diff. A
    reviewer who cannot see what moved will approve whatever moved."""
    rendered = baseline_from(a_report()).to_json()

    assert rendered.endswith("\n")
    assert '\n  "benign": {' in rendered
    assert json.loads(rendered)["version"] == BASELINE_VERSION


# ---------------------------------------------------------------------------
# Loading, defensively
# ---------------------------------------------------------------------------


def test_a_missing_baseline_says_how_to_make_one(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="--capture"):
        load_baseline(tmp_path / "absent.json")


def test_a_baseline_from_an_older_version_is_refused(tmp_path: Path) -> None:
    """Not silently upgraded. An old baseline compared field-by-field against a
    new report skips whatever the two versions do not share, which is a gate
    that passes because it stopped looking."""
    path = tmp_path / "eval-baseline.json"
    payload = json.loads(baseline_from(a_report()).to_json())
    payload["version"] = 0
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="version"):
        load_baseline(path)


def test_a_malformed_baseline_names_what_is_missing(tmp_path: Path) -> None:
    path = tmp_path / "eval-baseline.json"
    payload = json.loads(baseline_from(a_report()).to_json())
    del payload["families"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="missing or malformed"):
        load_baseline(path)


# ---------------------------------------------------------------------------
# The three outcomes
# ---------------------------------------------------------------------------


def test_an_unchanged_run_is_acceptable_and_not_stale() -> None:
    comparison = compare(a_baseline(), a_report())

    assert comparison.acceptable
    assert not comparison.stale
    assert comparison == compare(a_baseline(), a_report())


def test_more_false_positives_is_a_regression() -> None:
    comparison = compare(a_baseline(benign_flagged=0), a_report())

    assert not comparison.acceptable
    assert any("benign documents flagged" in line for line in comparison.regressions)


def test_a_newly_withheld_benign_document_is_a_regression() -> None:
    """**The worst thing this gate can catch**, and why `withheld` is tracked
    separately from `flagged`.

    A flagged benign document costs an analyst an afternoon. A withheld one is a
    document somebody legitimately needed and did not get, and it is how a
    security control ends up switched off. Both baselines below have the same
    corpus size; only the outcome moved.
    """
    clean_run = report(benign(CLEAN), attacks())
    stopped_run = report(benign(WITHHELD), attacks())

    assert baseline_from(clean_run).benign_withheld == 0
    assert baseline_from(stopped_run).benign_withheld == 1

    comparison = compare(baseline_from(clean_run), stopped_run)

    assert not comparison.acceptable
    assert any("WITHHELD" in line for line in comparison.regressions)


def test_a_benign_document_that_stops_being_withheld_is_an_improvement() -> None:
    """The same pair, the other way round. Directional, not any-change."""
    comparison = compare(
        baseline_from(report(benign(WITHHELD), attacks())),
        report(benign(CLEAN), attacks()),
    )

    assert comparison.acceptable
    assert comparison.stale


def test_less_detection_is_a_regression() -> None:
    families = {"exfiltration": FamilyCounts(total=1, detected=1, withheld=0)}
    comparison = compare(a_baseline(families=families), a_report())

    assert comparison.acceptable  # unchanged

    better = {"exfiltration": FamilyCounts(total=1, detected=1, withheld=1)}
    regressed = compare(a_baseline(families=better), a_report())

    assert not regressed.acceptable
    assert any("exfiltration withheld" in line for line in regressed.regressions)


def test_more_detection_is_an_improvement_not_a_failure() -> None:
    """A gate that failed on any change is a gate people disable the first time
    they improve something."""
    families = {"exfiltration": FamilyCounts(total=1, detected=0, withheld=0)}

    comparison = compare(a_baseline(families=families), a_report())

    assert comparison.acceptable
    assert comparison.stale
    assert any("exfiltration detected" in line for line in comparison.improvements)


def test_a_grown_corpus_is_structural_not_a_regression() -> None:
    """**The outcome a simpler design gets wrong.**

    Adding a benign document changes every rate in the report without anything
    about the firewall changing. Reported as a regression it sends somebody
    hunting a bug that is really a document they wrote; reported as a pass it
    lets a corpus change smuggle one through.
    """
    comparison = compare(a_baseline(benign_total=1), a_report())

    assert not comparison.acceptable
    assert comparison.structural
    assert comparison.regressions == ()
    assert any("benign corpus size changed" in line for line in comparison.structural)


def test_a_changed_deployment_is_structural() -> None:
    """`disallowed_url` and `tool_name_mention` are entirely a function of the
    allow-list and the catalogue, so counts either side of a deployment change
    were never comparable."""
    comparison = compare(a_baseline(deployment="something else"), a_report())

    assert comparison.structural
    assert comparison.regressions == ()


def test_adding_a_detector_is_structural() -> None:
    """Turning the classifier on changes what the numbers describe. Comparing
    across that would credit the model with the patterns' work, or blame it for
    them."""
    comparison = compare(a_baseline(detectors=("patterns", "classifier")), a_report())

    assert comparison.structural


def test_a_new_attack_family_is_structural() -> None:
    families = dict(a_baseline().families)
    families["a_family_that_left"] = FamilyCounts(total=3, detected=3, withheld=0)

    comparison = compare(a_baseline(families=families), a_report())

    assert any("disappeared" in line for line in comparison.structural)


def test_structural_findings_suppress_the_count_diff_entirely() -> None:
    """Not merged into one list. When the ruler changed, a list of "regressions"
    derived from incomparable numbers is worse than no list."""
    comparison = compare(a_baseline(benign_total=99, benign_flagged=0), a_report())

    assert comparison.structural
    assert comparison.regressions == ()
    assert comparison.improvements == ()


# ---------------------------------------------------------------------------
# Per-reported-family counts
# ---------------------------------------------------------------------------


def test_a_detector_that_starts_hitting_benign_documents_is_caught() -> None:
    """Tracked per reported family, not only in the total: a detector can start
    firing on benign documents while another stops, leaving the overall flagged
    count unmoved."""
    reported = {"exfiltration": ReportedCounts(attack_hits=1, benign_hits=0)}

    comparison = compare(a_baseline(reported=reported), a_report())

    assert any("exfiltration false positives" in line for line in comparison.regressions)


def test_a_detector_that_stops_reporting_entirely_is_caught() -> None:
    """A missing row reads as zero. A detector that went silent is a regression
    even when no family total moved."""
    reported = dict(a_baseline().reported)
    reported["direct_override"] = ReportedCounts(attack_hits=4, benign_hits=0)

    comparison = compare(a_baseline(reported=reported), a_report())

    assert any("direct_override true positives" in line for line in comparison.regressions)


def test_the_gate_reads_the_same_report_the_humans_read() -> None:
    """One computation, two audiences. A gate with its own idea of the numbers
    would eventually disagree with the report somebody quotes."""
    current = a_report()

    assert compare(baseline_from(current), current).acceptable
