"""The learned classifier beside the pattern firewall, on the same documents (ADR 0075).

For each set: the learned classifier's flag rate, the firewall's (any finding) and
its withholding rate in enforce mode. Attack rates resample groups (one instruction
in many contexts); benign rates resample documents.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from acp.corpus.bipia import load_bipia
from acp.corpus.harness import DEFAULT_DEPLOYMENT, DEFAULT_SEED, _screen
from acp.corpus.loader import default_root
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion, measure, measure_clustered
from acp.corpus.training import Datasets, Example
from acp.firewall import Firewall

LABELS: Final = {1: "attacks", 0: "benign"}
TARGET_FPR: Final = 0.01
"""The report threshold's validation false-positive budget, for every learned model."""


class Scorer(Protocol):
    """Anything scored like `acp.firewall.learned.LearnedModel`: a document to a score."""

    @property
    def threshold(self) -> float: ...

    @property
    def enforce_threshold(self) -> float: ...

    def score(self, text: str) -> float: ...


@dataclass(frozen=True, slots=True)
class OperatingPoints:
    """Both thresholds and what they did on validation (ADR 0075's rules)."""

    threshold: float
    """The lowest with at most `TARGET_FPR` of benign documents at or above it."""
    fpr: float
    recall: float
    enforce_threshold: float
    """Above every benign validation score."""
    enforce_recall: float


def operating_points(
    benign: Sequence[float], attacks: Sequence[float], *, target_fpr: float = TARGET_FPR
) -> OperatingPoints:
    """Choose both thresholds from validation scores alone."""
    ordered = sorted(benign)
    allowed = math.floor(target_fpr * len(ordered))
    threshold = ordered[-(allowed + 1)] + 1e-9 if ordered else 0.5
    enforce = (ordered[-1] if ordered else 0.5) + 1e-6

    def share(scores: Sequence[float], bar: float) -> float:
        return sum(s >= bar for s in scores) / len(scores) if scores else 0.0

    return OperatingPoints(
        threshold=threshold,
        fpr=share(ordered, threshold),
        recall=share(attacks, threshold),
        enforce_threshold=enforce,
        enforce_recall=share(attacks, enforce),
    )


@dataclass(frozen=True, slots=True)
class Row:
    name: str
    kind: str
    """``attacks`` (rates are recall) or ``benign`` (rates are false positives)."""
    learned: Proportion
    """Scored at or above the report threshold."""
    learned_enforce: Proportion
    """Scored at or above the enforce threshold: what would be withheld."""
    patterns: Proportion
    """The firewall produced any finding."""
    withheld: Proportion
    """The firewall withheld the document in enforce mode."""


def _rate(
    examples: Sequence[Example], outcome: dict[str, bool], rng: random.Random, resamples: int
) -> Proportion:
    if examples and examples[0].label == 1:
        groups: dict[str, list[bool]] = {}
        for e in examples:
            groups.setdefault(e.group, []).append(outcome[e.id])
        return measure_clustered(list(groups.values()), rng=rng, resamples=resamples)
    return measure([outcome[e.id] for e in examples], rng=rng, resamples=resamples)


def compare(
    name: str,
    examples: Sequence[Example],
    model: Scorer,
    *,
    seed: int = DEFAULT_SEED,
    resamples: int = DEFAULT_RESAMPLES,
) -> list[Row]:
    """One row per label present in ``examples``."""
    firewall = Firewall(enforce=True)
    tools = DEFAULT_DEPLOYMENT.catalogue
    scores = {e.id: model.score(e.text) for e in examples}
    learned = {i: s >= model.threshold for i, s in scores.items()}
    enforced = {i: s >= model.enforce_threshold for i, s in scores.items()}
    screened = {e.id: _screen(firewall, e.text, doc_id=e.id, tools=tools) for e in examples}
    patterns = {i: bool(s.families) or s.withheld for i, s in screened.items()}
    withheld = {i: s.withheld for i, s in screened.items()}
    rng = random.Random(seed)  # noqa: S311 — reproducibility, not cryptography
    rows: list[Row] = []
    for label in (1, 0):
        members = [e for e in examples if e.label == label]
        if members:
            rows.append(
                Row(
                    name=name,
                    kind=LABELS[label],
                    learned=_rate(members, learned, rng, resamples),
                    learned_enforce=_rate(members, enforced, rng, resamples),
                    patterns=_rate(members, patterns, rng, resamples),
                    withheld=_rate(members, withheld, rng, resamples),
                )
            )
    return rows


def as_json(rows: Sequence[Row]) -> list[dict[str, object]]:
    def cell(p: Proportion) -> dict[str, object]:
        return {
            "hits": p.successes,
            "total": p.total,
            "rate": round(p.rate, 4),
            "low": None if p.interval.degenerate else round(p.interval.low, 4),
            "high": None if p.interval.degenerate else round(p.interval.high, 4),
        }

    return [
        {
            "set": r.name,
            "kind": r.kind,
            "learned": cell(r.learned),
            "learned_enforce": cell(r.learned_enforce),
            "patterns": cell(r.patterns),
            "withheld": cell(r.withheld),
        }
        for r in rows
    ]


def open_sets(data: Datasets) -> dict[str, list[Example]]:
    """Validation by source, then the report-only sets: what may be looked at freely."""
    sets: dict[str, list[Example]] = {}
    for e in data.validation:
        sets.setdefault(f"validation/{e.source}", []).append(e)
    for name, members in data.report.items():
        sets[name] = list(members)
    return sets


def sealed_sets(data: Datasets) -> dict[str, list[Example]]:
    """The sealed sets, then evasion v1 by disguise; empty unless ``data`` was unsealed."""
    if not data.sealed:
        return {}
    sets = {name: list(members) for name, members in data.sealed.items()}
    by_transform: dict[str, list[Example]] = {}
    for d in load_bipia(default_root() / "external" / "evasion"):
        by_transform.setdefault(f"evasion_v1/{d.category}", []).append(
            Example(d.id, d.text, 1, d.group, "evasion", d.planted)
        )
    sets.update(sorted(by_transform.items()))
    return sets


def score_sets(sets: dict[str, list[Example]], model: Scorer) -> list[Row]:
    rows: list[Row] = []
    for name, members in sets.items():
        rows += compare(name, members, model)
    return rows
