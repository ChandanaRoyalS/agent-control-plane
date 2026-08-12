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


# ---------------------------------------------------------------------------
# Remaining allowance — spelled the same way as the rate limiter's
# ---------------------------------------------------------------------------


def test_a_quota_refusal_carries_remaining_and_limit() -> None:
    """The same three fields as a rate-limit refusal, spelled identically. A
    refused agent should not have to work out *which* budget stopped it before
    it can read the answer."""
    quota = QuotaCounter(limit=10.0, window_seconds=60.0)
    assert quota.check("alice", 0.0, 8.0)

    with pytest.raises(QuotaExceededError) as raised:
        enforce_quota(quota, "alice", 0.0, 5.0)

    details = raised.value.details
    assert details["limit"] == 10.0
    assert details["retry_after"] > 0
    # Two units left, and the refused call wanted five — so the allowance is
    # non-zero even though the call was refused.
    assert details["remaining"] == 2.0


def test_a_refused_quota_call_leaves_the_allowance_spendable() -> None:
    """The case where the number earns its place. A quota refuses a call that
    would *exceed* the window, so a caller with two left asking for ten is
    refused with two still available — and can spend them on something cheaper
    instead of waiting out the window."""
    quota = QuotaCounter(limit=10.0, window_seconds=60.0)
    quota.check("alice", 0.0, 8.0)

    with pytest.raises(QuotaExceededError):
        enforce_quota(quota, "alice", 0.0, 5.0)

    assert quota.check("alice", 0.0, 2.0), "the remaining allowance is genuinely spendable"
