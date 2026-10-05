"""The learned classifier beside the pattern firewall, on the same documents (ADR 0075).

For each set: the learned classifier's flag rate, the firewall's (any finding) and
its withholding rate in enforce mode. Attack rates resample groups (one instruction
in many contexts); benign rates resample documents.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from acp.corpus.harness import DEFAULT_DEPLOYMENT, DEFAULT_SEED, _screen
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion, measure, measure_clustered
from acp.corpus.training import Example
from acp.firewall import Firewall
from acp.firewall.learned import LearnedModel

LABELS: Final = {1: "attacks", 0: "benign"}


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
    model: LearnedModel,
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
