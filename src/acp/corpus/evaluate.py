"""Scoring the firewall against each attack's expected outcome, per family.

The seed of `acp.corpus.harness`. No aggregate detection rate is computed: it
would depend on how many attacks of each family were written (ADR 0036).
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
    """What the firewall does with one document, as an `Expectation`."""
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
    """Attack ids whose outcome differed from the expectation; empty means passing."""

    @property
    def caught(self) -> int:
        """Withheld or detected."""
        return self.withheld + self.detected

    @property
    def catch_rate(self) -> float:
        """Share of this family with any finding (per family only, by design)."""
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
