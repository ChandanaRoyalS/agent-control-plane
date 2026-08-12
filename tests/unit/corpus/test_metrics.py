"""Proportions with bootstrap intervals.

The interval is the whole point of this module — a bare 75% over 8 documents
reads exactly like a 75% over 8,000 — so most of what is asserted here is that
the interval says something true about how little the data supports the number.

Including the case where it cannot: when every observation agrees, the percentile
bootstrap returns a point, and reporting that as a tight interval would make the
harness's weakest rows look like its strongest.
"""

from __future__ import annotations

import random

from acp.corpus.metrics import EMPTY, Interval, bootstrap, measure

SEED = 20260812
FAST = 400
"""Enough resamples for a stable percentile, few enough to keep the suite quick.

The script's default is 2,000; nothing asserted here depends on the difference.
"""


def rng() -> random.Random:
    return random.Random(SEED)  # noqa: S311 — reproducibility, not cryptography


# ---------------------------------------------------------------------------
# The degenerate cases, which are the ones that matter
# ---------------------------------------------------------------------------


def test_no_observations_buys_the_whole_range() -> None:
    assert bootstrap([], rng=rng()) == EMPTY
    assert EMPTY.degenerate


def test_a_unanimous_sample_is_marked_uninformative_not_certain() -> None:
    """**The bootstrap's real limitation, surfaced rather than hidden.**

    Every resample of eight identical values is eight identical values, so the
    percentile interval collapses to a point. That point is not certainty — it
    is the estimator running out of things to say. A harness that printed
    `[0%, 0%]` here would be claiming its least-supported row was its most
    confident one.
    """
    none_caught = bootstrap([False] * 8, rng=rng(), resamples=FAST)
    all_caught = bootstrap([True] * 8, rng=rng(), resamples=FAST)

    assert none_caught == Interval(low=0.0, high=0.0, degenerate=True)
    assert all_caught == Interval(low=1.0, high=1.0, degenerate=True)
    assert none_caught.render() == "[uninformative]"


def test_one_dissenting_observation_makes_the_interval_informative() -> None:
    """The moment there is any variation, the resamples disagree and the interval
    becomes a real one — and it is wide, which is the honest answer for n=8."""
    interval = bootstrap([True] * 7 + [False], rng=rng(), resamples=FAST)

    assert not interval.degenerate
    assert interval.low < interval.high


# ---------------------------------------------------------------------------
# The interval behaves like an interval
# ---------------------------------------------------------------------------


def test_the_interval_contains_the_point_estimate() -> None:
    outcomes = [True] * 30 + [False] * 70

    result = measure(outcomes, rng=rng(), resamples=FAST)

    assert result.interval.low <= result.rate <= result.interval.high


def test_a_bigger_sample_at_the_same_rate_gives_a_tighter_interval() -> None:
    """The property the whole module exists for: n is what buys confidence, and
    the interval is where a reader sees it. Same 30% both times."""
    small = measure([True] * 3 + [False] * 7, rng=rng(), resamples=FAST)
    large = measure([True] * 300 + [False] * 700, rng=rng(), resamples=FAST)

    assert small.rate == large.rate
    assert (large.interval.high - large.interval.low) < (small.interval.high - small.interval.low)


def test_the_interval_never_leaves_zero_to_one() -> None:
    """Where the normal approximation this deliberately avoids goes wrong: a Wald
    interval on a rate near the boundary runs below 0 or above 1, and a
    false-positive rate of -3% is not a thing that can be reported."""
    result = measure([True] + [False] * 99, rng=rng(), resamples=FAST)

    assert 0.0 <= result.interval.low <= result.interval.high <= 1.0


def test_a_wider_confidence_gives_a_wider_interval() -> None:
    outcomes = [True] * 20 + [False] * 30

    ninety = bootstrap(outcomes, rng=rng(), resamples=FAST, confidence=0.90)
    ninety_nine = bootstrap(outcomes, rng=rng(), resamples=FAST, confidence=0.99)

    assert (ninety_nine.high - ninety_nine.low) >= (ninety.high - ninety.low)


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------


def test_the_same_seed_gives_the_same_interval() -> None:
    """An interval that moves when nothing moved is one a reader learns to
    ignore, which costs the harness the thing it was built for. The generator is
    injected for exactly this reason — the same discipline as the rate limiter's
    injected clock."""
    outcomes = [True] * 12 + [False] * 18

    first = bootstrap(outcomes, rng=rng(), resamples=FAST)
    second = bootstrap(outcomes, rng=rng(), resamples=FAST)

    assert first == second


def test_a_different_seed_gives_a_similar_but_not_identical_interval() -> None:
    """It is a resampling estimate, not an exact quantity. Asserted so nobody
    later 'fixes' the seeding into something that silently returns a constant."""
    outcomes = [True] * 12 + [False] * 18

    first = bootstrap(outcomes, rng=random.Random(1), resamples=FAST)  # noqa: S311
    second = bootstrap(outcomes, rng=random.Random(2), resamples=FAST)  # noqa: S311

    assert first != second
    assert abs(first.low - second.low) < 0.15


# ---------------------------------------------------------------------------
# Proportion
# ---------------------------------------------------------------------------


def test_a_proportion_counts_what_it_measured() -> None:
    result = measure([True, False, True, True], rng=rng(), resamples=FAST)

    assert result.successes == 3
    assert result.total == 4
    assert result.rate == 0.75


def test_an_empty_proportion_does_not_divide_by_zero() -> None:
    result = measure([], rng=rng())

    assert result.rate == 0.0
    assert result.interval.degenerate
