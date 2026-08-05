"""Unit tests for chaos-mode resolution.

The header-beats-environment precedence is the part worth pinning: tests set a
header per request, while docker-compose sets an environment variable for a
whole process, and those two must not fight.
"""

from __future__ import annotations

import pytest

from acp.mocks.chaos import ChaosMode, oversized_text, resolve_mode, resolve_param


def test_no_header_and_no_env_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHAOS_MODE", raising=False)

    assert resolve_mode(None) is ChaosMode.NONE


def test_env_is_used_when_no_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAOS_MODE", "hang")

    assert resolve_mode(None) is ChaosMode.HANG


def test_header_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAOS_MODE", "hang")

    assert resolve_mode("error") is ChaosMode.ERROR


def test_mode_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHAOS_MODE", raising=False)

    assert resolve_mode("ERROR") is ChaosMode.ERROR


def test_unknown_mode_raises_rather_than_silently_behaving_normally() -> None:
    """A typo must not masquerade as a healthy upstream."""
    with pytest.raises(ValueError, match="unknown chaos mode"):
        resolve_mode("hnag")


def test_param_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHAOS_PARAM", raising=False)

    assert resolve_param(None, default=1.5) == 1.5


def test_param_header_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAOS_PARAM", "9")

    assert resolve_param("3", default=1.0) == 3.0


def test_oversized_text_is_exactly_the_requested_length() -> None:
    assert len(oversized_text(1234)) == 1234


def test_oversized_text_is_deterministic() -> None:
    assert oversized_text(500) == oversized_text(500)
