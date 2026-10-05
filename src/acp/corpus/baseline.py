"""A committed baseline of what the firewall caught, and a diff against it (ADR 0047).

A baseline rather than a threshold, like `config/schema-baseline.json` (ADR 0013),
so accepting a regression is a reviewed diff. Compared by counts, since rates hide
their denominator. A comparison yields regressions, improvements, or a structural
change (corpus, families or deployment moved) where the runs are not comparable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acp.corpus.harness import Report
from acp.corpus.loader import default_root
from acp.exceptions import ConfigurationError

BASELINE_VERSION = 1
"""Bumped when the file's shape changes, so an old baseline fails loudly."""


@dataclass(frozen=True, slots=True)
class FamilyCounts:
    """One attack family: how many of it the firewall noticed and stopped."""

    total: int
    detected: int
    withheld: int


@dataclass(frozen=True, slots=True)
class ReportedCounts:
    """One family the firewall *reported*: what it hit, on each side."""

    attack_hits: int
    benign_hits: int


@dataclass(frozen=True, slots=True)
class Baseline:
    """What the firewall did, the last time somebody decided it was acceptable."""

    version: int
    deployment: str
    detectors: tuple[str, ...]
    benign_total: int
    benign_flagged: int
    benign_withheld: int
    families: dict[str, FamilyCounts]
    reported: dict[str, ReportedCounts]

    def to_json(self) -> str:
        """Sorted, indented JSON so a changed number is a one-line diff."""
        payload: dict[str, Any] = {
            "version": self.version,
            "deployment": self.deployment,
            "detectors": list(self.detectors),
            "benign": {
                "total": self.benign_total,
                "flagged": self.benign_flagged,
                "withheld": self.benign_withheld,
            },
            "families": {
                name: {"total": c.total, "detected": c.detected, "withheld": c.withheld}
                for name, c in sorted(self.families.items())
            },
            "reported": {
                name: {"attack_hits": c.attack_hits, "benign_hits": c.benign_hits}
                for name, c in sorted(self.reported.items())
            },
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def baseline_from(report: Report) -> Baseline:
    """The baseline a run would write, if somebody accepted its numbers."""
    return Baseline(
        version=BASELINE_VERSION,
        deployment=report.deployment,
        detectors=report.detectors,
        benign_total=report.false_positive_rate.total,
        benign_flagged=report.false_positive_rate.successes,
        benign_withheld=report.benign_withheld_rate.successes,
        families={
            row.family.value: FamilyCounts(
                total=row.detected.total,
                detected=row.detected.successes,
                withheld=row.withheld.successes,
            )
            for row in report.recall
        },
        reported={
            row.family.value: ReportedCounts(
                attack_hits=row.attack_hits, benign_hits=row.benign_hits
            )
            for row in report.precision
        },
    )


def load_baseline(path: Path) -> Baseline:
    """Read a committed baseline, or raise naming what stopped it."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = (
            f"cannot read the evaluation baseline {str(path)!r}: {exc}. "
            f"Create one with `python scripts/evaluate.py --capture`."
        )
        raise ConfigurationError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"the evaluation baseline {str(path)!r} is not valid JSON: {exc}"
        raise ConfigurationError(msg) from exc

    version = raw.get("version")
    if version != BASELINE_VERSION:
        msg = (
            f"the evaluation baseline {str(path)!r} is version {version!r}, "
            f"this build expects {BASELINE_VERSION}. Re-capture it — an old "
            f"baseline compared field-by-field against a new report silently "
            f"skips whatever the two versions do not share."
        )
        raise ConfigurationError(msg)

    try:
        benign = raw["benign"]
        return Baseline(
            version=version,
            deployment=str(raw["deployment"]),
            detectors=tuple(raw["detectors"]),
            benign_total=int(benign["total"]),
            benign_flagged=int(benign["flagged"]),
            benign_withheld=int(benign["withheld"]),
            families={
                name: FamilyCounts(
                    total=int(counts["total"]),
                    detected=int(counts["detected"]),
                    withheld=int(counts["withheld"]),
                )
                for name, counts in raw["families"].items()
            },
            reported={
                name: ReportedCounts(
                    attack_hits=int(counts["attack_hits"]),
                    benign_hits=int(counts["benign_hits"]),
                )
                for name, counts in raw["reported"].items()
            },
        )
    except (KeyError, TypeError, ValueError) as exc:
        msg = f"the evaluation baseline {str(path)!r} is missing or malformed: {exc}"
        raise ConfigurationError(msg) from exc


@dataclass(frozen=True)
class Comparison:
    """What changed between the committed baseline and this run."""

    structural: tuple[str, ...] = field(default_factory=tuple)
    """Why the runs are not comparable; needs a deliberate re-capture, not a fix."""

    regressions: tuple[str, ...] = field(default_factory=tuple)
    improvements: tuple[str, ...] = field(default_factory=tuple)

    @property
    def acceptable(self) -> bool:
        """Nothing got worse, and the two runs measured the same thing."""
        return not self.structural and not self.regressions

    @property
    def stale(self) -> bool:
        """The firewall improved, so the baseline should be re-captured (not a failure)."""
        return bool(self.improvements)


def _compare_counts(
    label: str,
    before: int,
    after: int,
    *,
    higher_is_better: bool,
    regressions: list[str],
    improvements: list[str],
) -> None:
    if after == before:
        return
    direction = "rose" if after > before else "fell"
    worse = (after < before) if higher_is_better else (after > before)
    line = f"{label}: {before} -> {after} ({direction} by {abs(after - before)})"
    (regressions if worse else improvements).append(line)


def compare(baseline: Baseline, report: Report) -> Comparison:
    """Diff a run against the baseline; any structural change is returned alone."""
    current = baseline_from(report)

    structural: list[str] = []
    if current.deployment != baseline.deployment:
        structural.append(f"deployment changed: {baseline.deployment!r} -> {current.deployment!r}")
    if current.detectors != baseline.detectors:
        structural.append(
            f"detectors changed: {list(baseline.detectors)} -> {list(current.detectors)}"
        )
    if current.benign_total != baseline.benign_total:
        structural.append(
            f"benign corpus size changed: {baseline.benign_total} -> {current.benign_total}"
        )

    for name in sorted(baseline.families.keys() | current.families.keys()):
        old = baseline.families.get(name)
        new = current.families.get(name)
        if old is None:
            structural.append(f"new attack family: {name} ({new.total if new else 0} attacks)")
        elif new is None:
            structural.append(f"attack family disappeared: {name}")
        elif old.total != new.total:
            structural.append(f"{name}: attack count changed, {old.total} -> {new.total}")

    if structural:
        return Comparison(structural=tuple(structural))

    regressions: list[str] = []
    improvements: list[str] = []

    _compare_counts(
        "benign documents flagged",
        baseline.benign_flagged,
        current.benign_flagged,
        higher_is_better=False,
        regressions=regressions,
        improvements=improvements,
    )
    _compare_counts(
        "benign documents WITHHELD",
        baseline.benign_withheld,
        current.benign_withheld,
        higher_is_better=False,
        regressions=regressions,
        improvements=improvements,
    )

    for name in sorted(current.families):
        old_family = baseline.families[name]
        new_family = current.families[name]
        _compare_counts(
            f"{name} detected",
            old_family.detected,
            new_family.detected,
            higher_is_better=True,
            regressions=regressions,
            improvements=improvements,
        )
        _compare_counts(
            f"{name} withheld",
            old_family.withheld,
            new_family.withheld,
            higher_is_better=True,
            regressions=regressions,
            improvements=improvements,
        )

    for name in sorted(baseline.reported.keys() | current.reported.keys()):
        # A missing row means nothing fired: count it as zero, in both directions.
        old_reported = baseline.reported.get(name, ReportedCounts(0, 0))
        new_reported = current.reported.get(name, ReportedCounts(0, 0))
        _compare_counts(
            f"{name} false positives",
            old_reported.benign_hits,
            new_reported.benign_hits,
            higher_is_better=False,
            regressions=regressions,
            improvements=improvements,
        )
        _compare_counts(
            f"{name} true positives",
            old_reported.attack_hits,
            new_reported.attack_hits,
            higher_is_better=True,
            regressions=regressions,
            improvements=improvements,
        )

    return Comparison(regressions=tuple(regressions), improvements=tuple(improvements))


def default_baseline_path(root: Path | None = None) -> Path:
    """The baseline path, beside the corpus it describes (not in `config/`)."""
    return (root or default_root()) / "eval-baseline.json"
