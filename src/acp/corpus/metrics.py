"""Proportions with percentile-bootstrap confidence intervals.

Bootstrap rather than Wald, which breaks at small n and rates near 0 or 1. When
every observation agrees the bootstrap collapses to a point, so such intervals
(and empty samples) are marked `degenerate` and rendered as uninformative.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

DEFAULT_RESAMPLES: Final = 2_000
"""Enough for the percentile estimate to be stable to about a percentage point."""

DEFAULT_CONFIDENCE: Final = 0.95


@dataclass(frozen=True, slots=True)
class Interval:
    """A confidence interval, and whether it is worth anything."""

    low: float
    high: float

    degenerate: bool = False
    """True when the sample was empty or unanimous, so the interval carries no information."""

    def render(self) -> str:
        if self.degenerate:
            return "[uninformative]"
        return f"[{self.low:.0%}, {self.high:.0%}]"


EMPTY: Final = Interval(low=0.0, high=1.0, degenerate=True)
"""The interval for no observations: the whole range, degenerate."""


@dataclass(frozen=True, slots=True)
class Proportion:
    """A count out of a total, with the interval that says how much to trust it."""

    successes: int
    total: int
    interval: Interval

    @property
    def rate(self) -> float:
        return self.successes / self.total if self.total else 0.0

    def render(self) -> str:
        return f"{self.rate:>6.1%}  {self.successes:>3}/{self.total:<3}  {self.interval.render()}"


def bootstrap(
    outcomes: Sequence[bool],
    *,
    rng: random.Random,
    resamples: int = DEFAULT_RESAMPLES,
    confidence: float = DEFAULT_CONFIDENCE,
) -> Interval:
    """A percentile bootstrap interval for the rate of ``True`` in ``outcomes``.

    ``rng`` is injected so a seeded run is reproducible.
    """
    total = len(outcomes)
    if total == 0:
        return EMPTY

    first = outcomes[0]
    if all(outcome is first for outcome in outcomes):
        # Every resample would be identical: a point, marked uninformative.
        rate = 1.0 if first else 0.0
        return Interval(low=rate, high=rate, degenerate=True)

    rates = sorted(
        sum(sample) / total for sample in (rng.choices(outcomes, k=total) for _ in range(resamples))
    )
    tail = (1.0 - confidence) / 2.0
    low = rates[int(tail * resamples)]
    high = rates[min(int((1.0 - tail) * resamples), resamples - 1)]
    return Interval(low=low, high=high)


def measure(
    outcomes: Sequence[bool],
    *,
    rng: random.Random,
    resamples: int = DEFAULT_RESAMPLES,
    confidence: float = DEFAULT_CONFIDENCE,
) -> Proportion:
    """The rate of ``True`` in ``outcomes``, with its bootstrap interval."""
    return Proportion(
        successes=sum(outcomes),
        total=len(outcomes),
        interval=bootstrap(outcomes, rng=rng, resamples=resamples, confidence=confidence),
    )


def measure_clustered(
    groups: Sequence[Sequence[bool]],
    *,
    rng: random.Random,
    resamples: int = DEFAULT_RESAMPLES,
    confidence: float = DEFAULT_CONFIDENCE,
) -> Proportion:
    """A rate over documents whose interval resamples whole groups, not documents.

    Documents in a group (one attack in many templates) are not independent, so
    the sample size is the number of groups.
    """
    flat = [outcome for group in groups for outcome in group]
    total = len(flat)
    successes = sum(flat)
    if total == 0:
        return Proportion(successes=0, total=0, interval=EMPTY)
    if successes in (0, total):
        rate = successes / total
        return Proportion(
            successes=successes,
            total=total,
            interval=Interval(low=rate, high=rate, degenerate=True),
        )
    sizes = [(sum(group), len(group)) for group in groups if group]
    if len({hits / n for hits, n in sizes}) == 1:
        # Equal group rates make every resample equal: a point, marked uninformative.
        rate = successes / total
        return Proportion(
            successes=successes,
            total=total,
            interval=Interval(low=rate, high=rate, degenerate=True),
        )
    rates: list[float] = []
    for _ in range(resamples):
        sample = rng.choices(sizes, k=len(sizes))
        drawn = sum(n for _, n in sample)
        rates.append(sum(hits for hits, _ in sample) / drawn)
    rates.sort()
    tail = (1.0 - confidence) / 2.0
    low = rates[int(tail * resamples)]
    high = rates[min(int((1.0 - tail) * resamples), resamples - 1)]
    return Proportion(successes=successes, total=total, interval=Interval(low=low, high=high))
