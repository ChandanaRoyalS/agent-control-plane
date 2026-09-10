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
    """True when the interval carries no information — an empty sample.

    It used to also cover the unanimous case, where the percentile bootstrap
    returns a single point because resampling identical values can only produce
    identical values. That is a true statement about the *bootstrap* and a false
    one about the data: `0 of 106` is a real observation with a real bound. Those
    now get an exact interval instead — see `exact` and `_exact_one_sided`.
    """

    exact: bool = False
    """True when this is a Clopper-Pearson interval rather than a bootstrap one.

    Marked because the two answer slightly different questions and a reader
    comparing a column of them is entitled to know which is which. An interval
    that is narrow because the data is unanimous and one that is narrow because
    the data is plentiful are still different claims; the `≤` in the rendering
    is what says so.
    """

    def render(self) -> str:
        if self.degenerate:
            return "[uninformative]"
        if self.exact and self.low == 0.0:
            return f"[≤{self.high:.1%} exact]"
        if self.exact and self.high == 1.0:
            return f"[≥{self.low:.1%} exact]"
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


def _exact_one_sided(*, successes: int, total: int, confidence: float) -> tuple[float, float]:
    """A Clopper-Pearson interval for a sample where every observation agreed.

    Exact rather than asymptotic, which matters at these sample sizes, and
    closed-form for the two boundary cases so no distribution library is needed:

    - zero successes in *n*: the upper bound is ``1 - alpha**(1/n)``
    - *n* successes in *n*: the lower bound is ``alpha**(1/n)``

    Both fall straight out of the binomial likelihood — the largest rate under
    which observing zero successes *n* times still has probability at least
    alpha. For 0 of 106 at 95%, that is 2.8%: small, bounded, and a far more
    useful sentence than "uninformative".
    """
    alpha = 1.0 - confidence
    if successes == 0:
        return (0.0, 1.0 - alpha ** (1.0 / total))
    return (alpha ** (1.0 / total), 1.0)


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
        # **The bootstrap has nothing to resample here, but the data is not
        # uninformative — the method is.**
        #
        # Every resample of an all-identical sample is identical, so the
        # percentile interval collapses to a point and this used to report
        # `[uninformative]`. That is the correct thing to say about the
        # bootstrap and the wrong thing to say about the observation: `0/106`
        # is a real result with a real bound, and it is the number the README
        # leads with. Reporting it as unquantified understated the strongest
        # measurement in the corpus.
        #
        # Clopper-Pearson is exact for this case and needs no resampling. See
        # `_exact_one_sided`.
        low, high = _exact_one_sided(
            successes=total if first else 0, total=total, confidence=confidence
        )
        return Interval(low=low, high=high, degenerate=False, exact=True)

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
