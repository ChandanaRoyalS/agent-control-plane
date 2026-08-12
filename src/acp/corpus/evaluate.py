"""Scoring the firewall against the corpus, sliced the way the corpus is sliced.

This is the seed of task 52's harness — precision, recall and false-positive
rate with confidence intervals — built now at the depth task 49 needs: run each
attack through the firewall, compare the outcome to what the corpus expected,
and report per family. The confidence intervals and the held-out split come
later; the shape does not change.

**One number is banned here on purpose: a single detection rate.** ADR 0036
argued it and this makes it structural — `Scoreboard` reports per family and
refuses to compute an aggregate, because an aggregate over families that
includes `plain_assertion` (which nothing catches) and `obfuscation` (which is
mostly withheld) is a number whose value depends entirely on how many of each
you wrote. The families are the result.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass

from acp.corpus.attack import Attack, AttackFamily, Expectation
from acp.firewall import Firewall
from acp.upstream.models import CallToolResult, ContentBlock


def outcome_of(firewall: Firewall, text: str, *, tools: AbstractSet[str]) -> Expectation:
    """What the firewall actually does with one document, in the corpus's own
    vocabulary so the two can be compared directly."""
    result = CallToolResult(content=[ContentBlock(type="text", text=text)], isError=False)
    inspection = firewall.inspect(result, tool="docs__read_document", tools=frozenset(tools))
    if inspection.refused:
        return Expectation.WITHHELD
    if inspection.screening.findings:
        return Expectation.DETECTED
    return Expectation.UNDETECTED


@dataclass(frozen=True, slots=True)
class FamilyScore:
    """One family's row in the scoreboard."""

    family: AttackFamily
    total: int
    withheld: int
    detected: int
    undetected: int
    mismatches: tuple[str, ...]
    """Attack ids whose actual outcome differed from the corpus's expectation.
    Empty is the passing state — an expectation the firewall no longer meets is
    a behaviour change somebody has to acknowledge, in either direction."""

    @property
    def caught(self) -> int:
        """Withheld or detected — the firewall did *something*."""
        return self.withheld + self.detected

    @property
    def catch_rate(self) -> float:
        """The share of this family the firewall produced any finding for.

        Per family only. There is deliberately no corpus-wide equivalent — see
        the module docstring.
        """
        return self.caught / self.total if self.total else 0.0


@dataclass(frozen=True)
class Scoreboard:
    """The whole evaluation, one row per family."""

    rows: tuple[FamilyScore, ...]

    @property
    def matched(self) -> bool:
        """Every attack did what the corpus said it would."""
        return all(not row.mismatches for row in self.rows)

    @property
    def all_mismatches(self) -> tuple[str, ...]:
        return tuple(m for row in self.rows for m in row.mismatches)


def evaluate(
    firewall: Firewall, attacks: Sequence[Attack], *, tools: AbstractSet[str]
) -> Scoreboard:
    """Run every attack through the firewall and score it against its family."""
    by_family: dict[AttackFamily, list[Attack]] = {}
    for attack in attacks:
        by_family.setdefault(attack.family, []).append(attack)

    rows: list[FamilyScore] = []
    for family in sorted(by_family, key=lambda f: f.value):
        counts: Counter[Expectation] = Counter()
        mismatches: list[str] = []
        for attack in by_family[family]:
            actual = outcome_of(firewall, attack.text, tools=tools)
            counts[actual] += 1
            if actual is not attack.expect:
                mismatches.append(attack.id)
        rows.append(
            FamilyScore(
                family=family,
                total=sum(counts.values()),
                withheld=counts[Expectation.WITHHELD],
                detected=counts[Expectation.DETECTED],
                undetected=counts[Expectation.UNDETECTED],
                mismatches=tuple(mismatches),
            )
        )
    return Scoreboard(rows=tuple(rows))
