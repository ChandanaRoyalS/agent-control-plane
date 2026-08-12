"""Settings to firewall — task 47's half of a gap this project keeps hitting.

`gateway_from_settings` has silently dropped new wiring four separate times
(tasks 22, 29, 43 and 46). Each time the feature was built, tested, merged, and
did nothing in a real deployment, because the only thing that could have noticed
was a test of the assembly rather than of the parts.

So this asserts the assembly: that a mode in an environment variable becomes a
firewall that behaves that way, that the host list survives the journey, and
that the two configurations which look like they are doing more than they are
say so out loud.
"""

from __future__ import annotations

import logging

import pytest

from acp.config import GatewaySettings
from acp.firewall import Mode
from acp.runtime import build_firewall
from acp.upstream.models import CallToolResult, ContentBlock

pytestmark = pytest.mark.integration

RLO = "\u202e"


def settings_for(
    *,
    firewall_mode: Mode = Mode.OFF,
    firewall_allowed_hosts: list[str] | None = None,
    provenance_framing_enabled: bool = False,
) -> GatewaySettings:
    """Settings with the firewall fields named explicitly.

    A `**overrides` splat would be shorter and is the thing this project has a
    standing rule against: pydantic types every field, and a splat of
    `dict[str, object]` erases all of it — `mypy --strict` then reports one
    error per field type the model declares. Named parameters keep the checking
    that makes the model worth having.
    """
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_required=False,
        firewall_mode=firewall_mode,
        firewall_allowed_hosts=firewall_allowed_hosts or [],
        provenance_framing_enabled=provenance_framing_enabled,
    )


def poisoned() -> CallToolResult:
    return CallToolResult(
        content=[ContentBlock(type="text", text=f"the figures{RLO}")], isError=False
    )


def image(host: str) -> CallToolResult:
    return CallToolResult(
        content=[ContentBlock(type="text", text=f"![logo](https://{host}/logo.png)")],
        isError=False,
    )


def test_the_default_deployment_screens_nothing() -> None:
    """Off by default: screening is linear in the size of every result, and a
    control that turns itself on is a control nobody chose."""
    assert build_firewall(settings_for()) is None


def test_report_mode_builds_a_firewall_that_does_not_withhold() -> None:
    firewall = build_firewall(settings_for(firewall_mode=Mode.REPORT))
    assert firewall is not None

    inspection = firewall.inspect(poisoned(), tool="mock-a__search")

    assert not inspection.refused
    assert inspection.triggers, "report mode should still evaluate the bar"


def test_enforce_mode_builds_a_firewall_that_withholds() -> None:
    firewall = build_firewall(settings_for(firewall_mode=Mode.ENFORCE))
    assert firewall is not None

    assert firewall.inspect(poisoned(), tool="mock-a__search").refused


def test_the_configured_hosts_reach_the_firewall() -> None:
    """A host list carried from an environment variable to a frozenset four
    function calls away, asserted by behaviour rather than by reading a private
    attribute — because what matters is the finding it changes.

    On the findings rather than on a refusal: the benign corpus demoted the
    image detector, so this list decides what is *reported*, which is what tasks
    51 and 52 will combine with a second signal.
    """
    firewall = build_firewall(
        settings_for(firewall_mode=Mode.ENFORCE, firewall_allowed_hosts=["cdn.corp"])
    )
    assert firewall is not None

    assert firewall.inspect(image("cdn.corp"), tool="t").screening.clean
    assert firewall.inspect(image("evil.test"), tool="t").screening.findings


def test_enforcing_without_framing_says_so(caplog: pytest.LogCaptureFixture) -> None:
    """ADR 0038's interlock, and the reason it is a warning rather than a
    refusal to start.

    The refusal notice is the gateway speaking, so it is deliberately not
    fenced — which means that with framing on, an unfenced block is by
    construction the gateway, and with framing off a hostile document can
    impersonate a refusal. The content is still withheld either way, so a
    deployment can adopt the two controls in either order; it should simply know
    which half it has.
    """
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        build_firewall(settings_for(firewall_mode=Mode.ENFORCE))

    assert any(r.message == "firewall.enforcing_without_framing" for r in caplog.records)


def test_the_complete_configuration_warns_about_nothing(caplog: pytest.LogCaptureFixture) -> None:
    """The other side of both warnings, which is the half worth asserting.

    A test that only proves a warning fires will pass just as happily against a
    `logger.warning` with no condition on it at all — and a startup that warns
    unconditionally is one whose warnings stop being read.
    """
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        build_firewall(
            settings_for(
                firewall_mode=Mode.ENFORCE,
                firewall_allowed_hosts=["cdn.corp"],
                provenance_framing_enabled=True,
            )
        )

    assert [r.message for r in caplog.records if r.name == "acp.runtime"] == []


def test_screening_with_no_allowed_hosts_says_so(caplog: pytest.LogCaptureFixture) -> None:
    """With no hosts configured the URL and image detectors report every link
    and every image in every document. Nothing is withheld either way — the
    benign corpus demoted both (ADR 0039) — but the finding count becomes noise,
    and a finding count that is mostly noise is how a log stops being read."""
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        build_firewall(settings_for(firewall_mode=Mode.REPORT))

    assert any(r.message == "firewall.every_link_reported" for r in caplog.records)


def test_a_configured_firewall_is_announced_at_startup(caplog: pytest.LogCaptureFixture) -> None:
    """An operator should be able to see which detectors are allowed to withhold
    a result without reading the source, because "why was this refused" starts
    with "what can refuse"."""
    with caplog.at_level(logging.INFO, logger="acp.runtime"):
        build_firewall(settings_for(firewall_mode=Mode.REPORT, firewall_allowed_hosts=["cdn.corp"]))

    enabled = [r for r in caplog.records if r.message == "firewall.enabled"]
    assert enabled
    assert enabled[0].mode == "report"  # type: ignore[attr-defined]
    assert "bidirectional_override" in enabled[0].enforceable_detectors  # type: ignore[attr-defined]
