"""What a bare `acp serve` runs, and what it says about it (ADR 0071).

The external review's W10: a bare gateway ran with no audit chain and no
firewall, and nothing a person would read said so — in a project whose own
ADR 0055 is titled "a control nobody runs is a control that does not exist".
These tests pin the defaults and the banner.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from acp.config import GatewaySettings
from acp.firewall.decision import Mode
from acp.runtime import SAFETY_CONTROLS, control_states, report_controls

pytestmark = pytest.mark.integration


def bare(**overrides: Any) -> GatewaySettings:
    """Settings as an unconfigured deployment has them: no env file, nothing set."""
    return GatewaySettings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_the_firewall_screens_by_default() -> None:
    """Report mode: every result screened, nothing a caller receives changed."""
    assert bare().firewall_mode is Mode.REPORT


def test_audit_and_authentication_are_both_required_by_default() -> None:
    settings = bare()

    assert settings.audit_required is True
    assert settings.auth_required is True


def test_the_banner_names_every_control() -> None:
    states = control_states(bare())

    assert set(SAFETY_CONTROLS) <= set(states)
    assert {"rate_limit", "quota", "result_cache", "approval_store", "budget_store"} <= set(states)


def test_the_banner_warns_when_a_safety_control_is_off(caplog: pytest.LogCaptureFixture) -> None:
    """The escape hatches are all real modes. None of them is quiet."""
    settings = bare(auth_required=False, audit_required=False, firewall_mode=Mode.OFF)

    with caplog.at_level(logging.INFO, logger="acp.runtime"):
        report_controls(settings)

    [warning] = [r for r in caplog.records if r.message == "gateway.safety_controls_off"]
    assert warning.levelno == logging.WARNING
    assert getattr(warning, "off", None) == ["authentication", "audit", "firewall"]


def test_a_fully_configured_gateway_does_not_warn(
    caplog: pytest.LogCaptureFixture, tmp_path: Any
) -> None:
    settings = bare(
        auth_issuer="https://idp.test/",
        auth_audience="agent-control-plane",
        auth_jwks_url="https://idp.test/keys",
        audit_file=tmp_path / "audit.jsonl",
    )

    with caplog.at_level(logging.INFO, logger="acp.runtime"):
        states = report_controls(settings)

    assert states["authentication"] == "on"
    assert states["audit"] == "on"
    assert states["firewall"] == "report"
    assert not [r for r in caplog.records if r.message == "gateway.safety_controls_off"]
    [info] = [r for r in caplog.records if r.message == "gateway.controls"]
    assert getattr(info, "controls", None) == states
