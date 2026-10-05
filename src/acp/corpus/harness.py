"""The evaluation harness: false-positive rate first, then recall, then precision (ADR 0046).

Recall is sliced by the family the corpus assigned; precision by the family the
firewall reported, over both corpora, as a separate table. Every rate carries a
bootstrap interval. No aggregate detection rate (ADR 0036). The held-out split is
named and counted in every report but scored only behind a flag (ADR 0041).
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from typing import Final

from acp.corpus.attack import Attack, AttackFamily, Expectation
from acp.corpus.loader import AttackCorpus, Corpus
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion, measure
from acp.firewall import Family, Firewall
from acp.upstream.models import CallToolResult, ContentBlock


@dataclass(frozen=True, slots=True)
class Deployment:
    """The single configuration both corpora are screened under.

    Precision mixes benign and attack hits, so both must see one firewall: the
    union of each corpus's hosts and tools, which does not flatter the firewall.
    """

    allowed_hosts: frozenset[str]
    catalogue: frozenset[str]

    def describe(self) -> str:
        return (
            f"{len(self.allowed_hosts)} allowed hosts, {len(self.catalogue)} tools in the catalogue"
        )


DEFAULT_DEPLOYMENT: Final = Deployment(
    allowed_hosts=frozenset(
        {
            # The benign corpus's organisation.
            "wiki.internal",
            "cdn.internal",
            "app.acme.example",
            # The attack corpus's.
            "docs.corp",
            "cdn.corp",
            # In both.
            "acme.example",
        }
    ),
    catalogue=frozenset(
        {
            # Named in the benign corpus's own audit logs and decision records.
            "crm__search",
            "crm__delete_record",
            "docs__read_document",
            "billing__issue_refund",
            # Named by the tool-confusion attacks; omitting them would flatter the firewall.
            "mock-a__search",
            "mock-a__create_ticket",
            "mock-b__delete_record",
            "mock-b__summarize",
        }
    ),
)


DEFAULT_SEED = 20260812
"""Fixed, so an unchanged firewall reports the same intervals every run."""


# ---------------------------------------------------------------------------
# One document, screened
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Screened:
    """What the firewall did to one document, in the terms both tables need."""

    id: str
    families: frozenset[Family]
    """Families the firewall reported (not the document's own); precision counts these."""

    withheld: bool

    @property
    def flagged(self) -> bool:
        """Any finding at all: the bar for the false-positive rate."""
        return bool(self.families)


def _screen(firewall: Firewall, text: str, *, doc_id: str, tools: AbstractSet[str]) -> Screened:
    result = CallToolResult(content=[ContentBlock(type="text", text=text)], isError=False)
    inspection = firewall.inspect(result, tool="docs__read_document", tools=frozenset(tools))
    # Include triggers so a tail-withheld document (ADR 0069) counts as detected.
    flagged = (*inspection.screening.findings, *inspection.triggers)
    return Screened(
        id=doc_id,
        families=frozenset(finding.family for finding in flagged),
        withheld=inspection.refused,
    )


# ---------------------------------------------------------------------------
# The rows
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecallRow:
    """One attack family, as the corpus assigned it: how much the firewall noticed."""

    family: AttackFamily
    detected: Proportion
    """Produced any finding."""

    withheld: Proportion
    """Actually withheld; never exceeds `detected`."""

    expected_undetected: int
    """Attacks expected `undetected`; still in the denominator (ADR 0040)."""

    mismatches: tuple[str, ...]
    """Attacks whose outcome differed from the expectation, in either direction."""


@dataclass(frozen=True, slots=True)
class PrecisionRow:
    """One reported family: how much of what the firewall called this was an attack."""

    family: Family
    precision: Proportion
    """Share of documents flagged with this family that were attacks (both corpora)."""

    benign_hits: int
    attack_hits: int


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Report:
    """Everything the harness measured, in the order it should be read."""

    false_positive_rate: Proportion
    """Benign documents the firewall produced any finding for."""

    benign_withheld_rate: Proportion
    """Benign documents the firewall actually withheld."""

    recall: tuple[RecallRow, ...]
    precision: tuple[PrecisionRow, ...]

    benign_flagged: tuple[str, ...]
    """IDs of benign documents that tripped a detector (ADR 0039)."""

    heldout_notice: str
    """The sealed split, named and counted, in the report's own output."""

    detectors: tuple[str, ...]
    """Detectors attached for this run (shows whether the classifier was on)."""

    deployment: str = ""
    """The deployment screened under, in words; URL and tool-name results depend on it."""

    seed: int = DEFAULT_SEED
    resamples: int = DEFAULT_RESAMPLES

    scored_heldout: bool = False
    """True only when the held-out flag was passed."""

    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def all_mismatches(self) -> tuple[str, ...]:
        return tuple(m for row in self.recall for m in row.mismatches)

    @property
    def matched(self) -> bool:
        """Every attack did what the corpus said it would."""
        return not self.all_mismatches


# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------


def evaluate_firewall(
    firewall: Firewall,
    *,
    benign: Corpus,
    attacks: AttackCorpus,
    deployment: Deployment = DEFAULT_DEPLOYMENT,
    heldout_notice: str,
    detectors: Sequence[str] = (),
    seed: int = DEFAULT_SEED,
    resamples: int = DEFAULT_RESAMPLES,
    scored_heldout: bool = False,
) -> Report:
    """Screen both corpora and build the report; deterministic for a given seed."""
    rng = random.Random(seed)  # noqa: S311 — reproducibility, not cryptography

    benign_screened = [
        _screen(firewall, document.text, doc_id=document.id, tools=deployment.catalogue)
        for document in benign.documents
    ]
    attack_screened = {
        attack.id: _screen(firewall, attack.text, doc_id=attack.id, tools=deployment.catalogue)
        for attack in attacks.attacks
    }

    false_positive_rate = measure(
        [screened.flagged for screened in benign_screened], rng=rng, resamples=resamples
    )
    benign_withheld_rate = measure(
        [screened.withheld for screened in benign_screened], rng=rng, resamples=resamples
    )

    recall = _recall_rows(attacks.attacks, attack_screened, rng=rng, resamples=resamples)
    precision = _precision_rows(
        benign_screened, list(attack_screened.values()), rng=rng, resamples=resamples
    )

    return Report(
        false_positive_rate=false_positive_rate,
        benign_withheld_rate=benign_withheld_rate,
        recall=recall,
        precision=precision,
        benign_flagged=tuple(
            sorted(screened.id for screened in benign_screened if screened.flagged)
        ),
        heldout_notice=heldout_notice,
        detectors=tuple(detectors),
        deployment=deployment.describe(),
        seed=seed,
        resamples=resamples,
        scored_heldout=scored_heldout,
        warnings=_warnings(recall, precision),
    )


def _recall_rows(
    attacks: Sequence[Attack],
    screened: dict[str, Screened],
    *,
    rng: random.Random,
    resamples: int,
) -> tuple[RecallRow, ...]:
    by_family: dict[AttackFamily, list[Attack]] = {}
    for attack in attacks:
        by_family.setdefault(attack.family, []).append(attack)

    rows: list[RecallRow] = []
    for family in sorted(by_family, key=lambda f: f.value):
        members = by_family[family]
        outcomes = [screened[attack.id] for attack in members]
        mismatches = [
            attack.id
            for attack in members
            if _expectation_of(screened[attack.id]) is not attack.expect
        ]
        rows.append(
            RecallRow(
                family=family,
                detected=measure(
                    [outcome.flagged for outcome in outcomes], rng=rng, resamples=resamples
                ),
                withheld=measure(
                    [outcome.withheld for outcome in outcomes], rng=rng, resamples=resamples
                ),
                expected_undetected=sum(
                    1 for attack in members if attack.expect is Expectation.UNDETECTED
                ),
                mismatches=tuple(mismatches),
            )
        )
    return tuple(rows)


def _precision_rows(
    benign: Sequence[Screened],
    attacks: Sequence[Screened],
    *,
    rng: random.Random,
    resamples: int,
) -> tuple[PrecisionRow, ...]:
    """One row per family the firewall reported; 0/0 families are omitted."""
    reported = sorted(
        {family for screened in (*benign, *attacks) for family in screened.families},
        key=lambda f: f.value,
    )
    rows: list[PrecisionRow] = []
    for family in reported:
        # True per attack hit, False per benign hit: the population precision describes.
        outcomes = [True for screened in attacks if family in screened.families]
        attack_hits = len(outcomes)
        benign_hits = sum(1 for screened in benign if family in screened.families)
        outcomes.extend([False] * benign_hits)
        rows.append(
            PrecisionRow(
                family=family,
                precision=measure(outcomes, rng=rng, resamples=resamples),
                benign_hits=benign_hits,
                attack_hits=attack_hits,
            )
        )
    return tuple(rows)


def _expectation_of(screened: Screened) -> Expectation:
    if screened.withheld:
        return Expectation.WITHHELD
    return Expectation.DETECTED if screened.families else Expectation.UNDETECTED


SMALL_SAMPLE = 10
"""Sample size below which a row gets a warning (rows are never filtered)."""


def _warnings(recall: Sequence[RecallRow], precision: Sequence[PrecisionRow]) -> tuple[str, ...]:
    """Caveats to print before anyone quotes a number from this report."""
    warnings: list[str] = []
    # One line per table, not per row, so the warnings stay readable.
    thin_recall = [row.family.value for row in recall if row.detected.total < SMALL_SAMPLE]
    if thin_recall:
        warnings.append(
            "fewer than "
            f"{SMALL_SAMPLE} attacks in "
            + ", ".join(thin_recall)
            + " — read the interval, not the percentage"
        )
    thin_precision = [row.family.value for row in precision if row.precision.total < SMALL_SAMPLE]
    if thin_precision:
        warnings.append(
            f"fewer than {SMALL_SAMPLE} flagged documents for "
            + ", ".join(thin_precision)
            + " — too few to quote"
        )
    degenerate = [row.family.value for row in recall if row.detected.interval.degenerate]
    if degenerate:
        warnings.append(
            "every observation agreed for "
            + ", ".join(degenerate)
            + " — the bootstrap cannot express uncertainty there, so those "
            "intervals are marked uninformative rather than tight"
        )
    return tuple(warnings)
