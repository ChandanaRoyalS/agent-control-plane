"""The evaluation harness: false-positive rate first, then recall, then precision.

Task 52. Everything before it built the firewall and the corpora; this is the
thing that says how well it works, and says it in an order that reflects what
actually gets a security control switched off.

**The false-positive rate comes first, and that is not a presentation choice.**
A firewall that withholds legitimate documents gets turned off, and once it is
off its recall is zero. So the first number in this report is the rate at which
the firewall does something to a document nobody should have been stopped from
reading — and the first *table*, not a footnote after the flattering figures.

**Recall and precision are sliced differently, and conflating them would be a
lie.** They are indexed by two different things that happen to share names:

- **Recall is sliced by what an attack *is*** — the family the corpus author
  assigned. "Of the eight `exfiltration` attacks I wrote, how many did the
  firewall notice?"
- **Precision is sliced by what the firewall *said*** — the family the detector
  reported. "Of everything the firewall called `exfiltration`, how much was
  actually an attack?"

Those are different denominators over different populations, and a single
per-family table carrying both would silently invite a reader to divide one by
the other. They are reported as two tables with the slicing named in each.

**There is no aggregate detection rate**, and `Scoreboard` refuses to compute one
for the reason ADR 0036 gives: an average over families that include
`plain_assertion` (which nothing catches, by construction) and `obfuscation`
(which is mostly withheld) is a number whose value is set by how many of each
somebody chose to write. It measures the corpus, not the firewall.

**The held-out split is named, counted, and not scored.** Its identity appears in
this report precisely so that the seal is visible in the artifact rather than
asserted in a document nobody opens — see `heldout_notice`. Scoring it requires
reaching past a deliberate flag, because a number you can re-run while tuning has
stopped being held out by about the third iteration (ADR 0041).
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
    """The one configuration both corpora are screened under.

    **This has to be one deployment, and getting it wrong quietly breaks
    precision.** The benign corpus was written for an organisation whose hosts
    are `wiki.internal` and whose catalogue contains `crm__search`; the attack
    corpus was written against `docs.corp` and `mock-a__search`. Screened under
    their own settings — which is what the existing corpus tests do, correctly,
    because each measures its own corpus — the two are being read by two
    different firewalls.

    A false-positive rate is fine that way; it is a statement about one corpus.
    **Precision is not.** It divides attack hits by attack hits plus benign hits,
    so a denominator assembled from two differently-configured firewalls is a
    ratio between numbers that were never comparable. So the harness screens
    everything under the union, and reports which union, because a number whose
    configuration is not stated is not reproducible.

    The union is also the honest direction. Adding the benign organisation's
    hosts to the allow-list cannot help an attack that exfiltrates to a host in
    neither corpus, and adding the attack corpus's tool names to the catalogue
    can only make `tool_name_mention` fire *more* — on both sides. Neither change
    flatters the firewall.
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
            # Named by the tool-confusion attacks. Included deliberately: a
            # catalogue those attacks cannot refer to is the flattering test,
            # not the fair one.
            "mock-a__search",
            "mock-a__create_ticket",
            "mock-b__delete_record",
            "mock-b__summarize",
        }
    ),
)


DEFAULT_SEED = 20260812
"""Fixed, so two runs of an unchanged firewall report the same intervals.

An interval that moves when nothing moved is one a reader learns to ignore.
"""


# ---------------------------------------------------------------------------
# One document, screened
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Screened:
    """What the firewall did to one document, in the terms both tables need."""

    id: str
    families: frozenset[Family]
    """The families the firewall *reported*, which is not the family the document
    *has*. A `direct_override` attack caught by the base64 detector is reported
    as `obfuscation`, and precision has to be counted on what was said."""

    withheld: bool

    @property
    def flagged(self) -> bool:
        """The firewall produced any finding at all — the loosest possible bar,
        and the right one for a false-positive rate. A benign document that
        merely trips a detector has already cost somebody an investigation."""
        return bool(self.families)


def _screen(firewall: Firewall, text: str, *, doc_id: str, tools: AbstractSet[str]) -> Screened:
    result = CallToolResult(content=[ContentBlock(type="text", text=text)], isError=False)
    inspection = firewall.inspect(result, tool="docs__read_document", tools=frozenset(tools))
    return Screened(
        id=doc_id,
        families=frozenset(finding.family for finding in inspection.screening.findings),
        withheld=inspection.refused,
    )


# ---------------------------------------------------------------------------
# The rows
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecallRow:
    """One attack family: how much of it the firewall noticed.

    Sliced by the family the *corpus* assigned.
    """

    family: AttackFamily
    detected: Proportion
    """Produced any finding. The loose bar."""

    withheld: Proportion
    """Actually stopped. The bar that matters to a caller, and always the lower
    of the two — a document can be flagged without being withheld, never the
    reverse."""

    expected_undetected: int
    """How many of these the corpus says nothing will ever catch.

    Not a failure and not excluded from the denominator. Recall computed over
    only the catchable attacks is a number about the corpus author's choices,
    and the families this project cannot catch are exactly the ones a reader
    should see in the same table as the ones it can (ADR 0040).
    """

    mismatches: tuple[str, ...]
    """Attacks whose outcome differed from the corpus's recorded expectation, in
    either direction — an improvement nobody noticed is still a behaviour change
    nobody acknowledged."""


@dataclass(frozen=True, slots=True)
class PrecisionRow:
    """One *reported* family: how much of what the firewall called this was real.

    Sliced by what the detector said, not by what the document was.
    """

    family: Family
    precision: Proportion
    """Of the documents the firewall flagged with this family, the share that
    were attacks. The denominator spans both corpora, which is the only way a
    precision figure means anything — precision computed over attacks alone is
    structurally 100% and measures nothing."""

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
    """Benign documents the firewall actually stopped. The one that gets a
    security control switched off, and the reason it is reported separately
    rather than folded into the line above."""

    recall: tuple[RecallRow, ...]
    precision: tuple[PrecisionRow, ...]

    benign_flagged: tuple[str, ...]
    """Which benign documents tripped a detector, by id.

    A rate tells you how often; only the list tells you *what*, and task 48's
    whole result came from reading the six documents rather than the 5.7%.
    """

    heldout_notice: str
    """The sealed split, named and counted, in the report's own output."""

    detectors: tuple[str, ...]
    """Which detectors were attached for this run, so a number produced with the
    optional classifier on cannot be mistaken for one produced without it."""

    deployment: str = ""
    """The configuration every document here was screened under, in words.

    Printed with the numbers rather than kept in a constant, because the
    `disallowed_url` and `tool_name_mention` detectors are *entirely* a function
    of it — the same corpus under a different allow-list produces a different
    false-positive rate, and a rate quoted without its deployment is a rate
    nobody can reproduce or dispute.
    """

    seed: int = DEFAULT_SEED
    resamples: int = DEFAULT_RESAMPLES

    scored_heldout: bool = False
    """True only when somebody passed the flag that opens the seal."""

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
    """Screen both corpora and build the report.

    Pure but for the firewall itself: given the same corpora and the same seed it
    produces the same intervals, which is what makes a change in a number mean a
    change in the firewall.
    """
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
    """One row per family the firewall actually reported.

    Families no detector produced are omitted rather than printed as 0/0: a row
    saying "of the nothing I flagged, none was real" is not a precision figure,
    and reporting it as one puts a meaningless zero next to meaningful ones.
    """
    reported = sorted(
        {family for screened in (*benign, *attacks) for family in screened.families},
        key=lambda f: f.value,
    )
    rows: list[PrecisionRow] = []
    for family in reported:
        # `True` for a hit on an attack, `False` for a hit on a benign document.
        # The bootstrap then runs over exactly the population the precision
        # figure describes: the documents this detector spoke about.
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
"""Below this, an interval is wide enough that the point estimate is decoration.

Not a threshold anything is filtered by — every row is still reported. It is the
size at which the harness says so out loud, because a reader scanning a table of
percentages will not stop to check each denominator.
"""


def _warnings(recall: Sequence[RecallRow], precision: Sequence[PrecisionRow]) -> tuple[str, ...]:
    """What a reader should be told before they quote a number from this report."""
    warnings: list[str] = []
    # Collapsed into one line per table rather than one per row. Every family in
    # this corpus is small, so a warning per row is a wall of text that reads as
    # boilerplate — and a warning nobody reads is not a warning.
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
