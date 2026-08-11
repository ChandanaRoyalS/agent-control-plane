"""Unit tests for quota enforcement."""

from __future__ import annotations

import pytest

from acp.budget import QuotaCounter, enforce_quota
from acp.exceptions import QuotaExceededError

T0 = 1000.0
WINDOW = 100.0


def test_within_quota_passes_silently() -> None:
    counter = QuotaCounter(limit=2, window_seconds=WINDOW)
    enforce_quota(counter, "alice", T0)


def test_over_quota_raises() -> None:
    counter = QuotaCounter(limit=1, window_seconds=WINDOW)
    enforce_quota(counter, "alice", T0)
    with pytest.raises(QuotaExceededError):
        enforce_quota(counter, "alice", T0)


def test_the_error_is_recoverable() -> None:
    counter = QuotaCounter(limit=1, window_seconds=WINDOW)
    enforce_quota(counter, "alice", T0)
    with pytest.raises(QuotaExceededError) as exc:
        enforce_quota(counter, "alice", T0)
    assert exc.value.recoverable is True


def test_the_error_carries_the_seconds_until_reset() -> None:
    counter = QuotaCounter(limit=1, window_seconds=WINDOW)
    enforce_quota(counter, "alice", T0 + 30.0)
    with pytest.raises(QuotaExceededError) as exc:
        enforce_quota(counter, "alice", T0 + 30.0)
    assert exc.value.details["retry_after"] == 70.0


def test_the_quota_recovers_in_the_next_window() -> None:
    counter = QuotaCounter(limit=1, window_seconds=WINDOW)
    enforce_quota(counter, "alice", T0)
    with pytest.raises(QuotaExceededError):
        enforce_quota(counter, "alice", T0)
    enforce_quota(counter, "alice", T0 + WINDOW)  # next window, passes


def test_cost_is_honoured() -> None:
    counter = QuotaCounter(limit=5, window_seconds=WINDOW)
    enforce_quota(counter, "alice", T0, cost=5.0)
    with pytest.raises(QuotaExceededError):
        enforce_quota(counter, "alice", T0, cost=1.0)
