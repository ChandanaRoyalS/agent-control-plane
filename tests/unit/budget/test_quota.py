"""Unit tests for the fixed-window quota counter.

Time is injected, so windows are exact: a window is ``floor(now / window)``, and
these tests advance ``now`` across window boundaries by hand.
"""

from __future__ import annotations

import pytest

from acp.budget import QuotaCounter

# A window covering [1000, 1100): index 10 of a 100-second window.
T0 = 1000.0
WINDOW = 100.0


def test_calls_within_the_limit_are_allowed() -> None:
    quota = QuotaCounter(limit=3, window_seconds=WINDOW)
    assert [quota.check("alice", T0) for _ in range(3)] == [True, True, True]


def test_the_limit_blocks_further_calls_in_the_window() -> None:
    quota = QuotaCounter(limit=2, window_seconds=WINDOW)
    assert quota.check("alice", T0)
    assert quota.check("alice", T0)
    assert quota.check("alice", T0) is False


def test_a_new_window_resets_the_allowance() -> None:
    """The defining behaviour: rolling into the next window restores the full
    allowance, regardless of how spent the previous one was."""
    quota = QuotaCounter(limit=1, window_seconds=WINDOW)
    assert quota.check("alice", T0)
    assert quota.check("alice", T0) is False
    assert quota.check("alice", T0 + WINDOW)  # next window, fresh


def test_time_within_the_same_window_does_not_reset() -> None:
    """Advancing but staying inside the window keeps the tally."""
    quota = QuotaCounter(limit=1, window_seconds=WINDOW)
    assert quota.check("alice", T0)
    assert quota.check("alice", T0 + WINDOW - 1.0) is False  # still window 10


def test_principals_have_independent_quotas() -> None:
    quota = QuotaCounter(limit=1, window_seconds=WINDOW)
    assert quota.check("alice", T0)
    assert quota.check("bob", T0)
    assert quota.check("alice", T0) is False


def test_cost_is_charged_against_the_window() -> None:
    quota = QuotaCounter(limit=10, window_seconds=WINDOW)
    assert quota.check("alice", T0, cost=6.0)
    assert quota.check("alice", T0, cost=6.0) is False  # 12 > 10
    assert quota.check("alice", T0, cost=4.0)  # 6 + 4 = 10, fits exactly


def test_resets_at_is_the_end_of_the_window() -> None:
    quota = QuotaCounter(limit=1, window_seconds=WINDOW)
    assert quota.resets_at(T0) == 1100.0
    assert quota.resets_at(T0 + 50.0) == 1100.0  # same window


def test_retry_after_counts_down_to_the_reset() -> None:
    quota = QuotaCounter(limit=1, window_seconds=WINDOW)
    assert quota.retry_after(T0) == 100.0
    assert quota.retry_after(T0 + 40.0) == 60.0


def test_a_non_positive_limit_is_rejected() -> None:
    with pytest.raises(ValueError, match="limit must be positive"):
        QuotaCounter(limit=0, window_seconds=WINDOW)


def test_a_non_positive_window_is_rejected() -> None:
    with pytest.raises(ValueError, match="window must be positive"):
        QuotaCounter(limit=1, window_seconds=0)
