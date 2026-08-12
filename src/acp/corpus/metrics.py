"""Proportions with confidence intervals, and honesty about when they mean little.

Every number this harness reports is a proportion over a corpus somebody wrote
by hand: 8 attacks in a family, 106 benign documents. A bare "75%" over 8
documents reads exactly like a 75% over 8,000 and is a completely different
claim, and the whole reason task 52 reports intervals is to stop that sentence
being written.

**Percentile bootstrap**, not a normal approximation. The Wald interval on a
proportion is the standard choice and it is wrong in precisely the cases this
corpus is full of — small n, and rates near 0 or 1, where it produces intervals
that run below zero or above one. Resampling the observed outcomes makes no
distributional assumption at all, and the cost — a few thousand resamples of a
list of booleans — is irrelevant for a corpus this size.

**And the failure mode the bootstrap has, stated rather than hidden.** When every
observation in a sample agrees — 0 of 8 caught, 12 of 12 caught — every resample
also agrees, so the interval collapses to a single point and claims certainty the
data does not support. This is a real and well-known limitation of the percentile
bootstrap, not a bug here, and the fix is not to paper over it with a different
estimator: it is to mark the interval `degenerate` so a reader is told the
interval is uninformative rather than being handed a spuriously tight one. A
harness whose weakest numbers look like its strongest is worse than no harness.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

DEFAULT_RESAMPLES: Final = 2_000
"""Enough that the percentile estimate is stable to about a percentage point.

More would be cheap and would not change a reported figure at this corpus size;
fewer starts to make the interval itself noisy, which is a strange thing for a
measure of noise to be.
"""

DEFAULT_CONFIDENCE: Final = 0.95


@dataclass(frozen=True, slots=True)
class Interval:
    """A confidence interval, and whether it is worth anything."""

    low: float
    high: float

    degenerate: bool = False
    """True when the interval carries no information.

    Either the sample was empty, or every observation in it agreed. In the second
    case the percentile bootstrap returns a single point — not because the
    estimate is certain, but because resampling identical values can only produce
    identical values. Reported rather than smoothed over: an interval that is
    narrow because the data is unanimous and an interval that is narrow because
    the data is plentiful are different claims, and only one of them is strong.
    """

    def render(self) -> str:
        if self.degenerate:
            return "[uninformative]"
        return f"[{self.low:.0%}, {self.high:.0%}]"


EMPTY: Final = Interval(low=0.0, high=1.0, degenerate=True)
"""What no observations buys you: the whole range, and a warning."""


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

    ``rng`` is injected rather than module-global, for the same reason the rate
    limiter takes ``now``: a measurement nobody can reproduce is a measurement
    nobody can check, and a seeded generator passed in makes the whole harness a
    pure function of its inputs.
    """
    total = len(outcomes)
    if total == 0:
        return EMPTY

    first = outcomes[0]
    if all(outcome is first for outcome in outcomes):
        # Every resample would be identical, so the percentile interval is a
        # point. Reported as uninformative rather than as certainty.
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
