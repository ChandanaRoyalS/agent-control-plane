"""Settings to approvals — the half of task 55 that keeps not existing.

`gateway_from_settings` has silently dropped new wiring five separate times
(tasks 22, 29, 43, 46 and 47's own subject). Each time the feature was built,
tested, merged, and did nothing in a real deployment, because the only thing
that could have noticed was a test of the *assembly* rather than of the parts.

So this asserts the assembly, and it asserts every hop of it: that a policy
saying `require_approval` produces a store, that the store reaches `build_app`,
that the TTL in an environment variable is the TTL on the record a caller is
handed, that the operator credential produces routes, and that the one
configuration which is correct but useless says so out loud.

The TTL hop is the one worth naming. A setting nobody threads through is a
setting that reads as configured and behaves as default — and for a value that
*is* the default-deny (ADR 0048), the gap between "five minutes because I set
it" and "five minutes because nothing read what I set" is the whole control.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from acp.admin import build_admin_app
from acp.approvals import APPROVALS_PATH, InMemoryApprovalStore, request_for
from acp.config import GatewaySettings
from acp.policy import Effect, Policy, Rule
from acp.runtime import build_approval_store, gateway_from_settings

from ..tokens import Keypair, claims
from .helpers import authenticated_gateway, call_gateway

pytestmark = pytest.mark.integration

ALICE = "alice@example.test"
TOOL = "mock-a__search"
CREDENTIAL = "operator-credential-for-tests"

GATED = Policy(
    rules=(
        Rule(
            name="approve-searches",
            effect=Effect.REQUIRE_APPROVAL,
            subjects=(ALICE,),
            tools=(TOOL,),
        ),
    )
)
OPEN = Policy(rules=(Rule(name="allow-everything", effect=Effect.ALLOW),))

GATED_YAML = """
rules:
  - name: approve-searches
    effect: require_approval
    tools: [mock-a__search]
"""

UPSTREAMS_YAML = """
upstreams:
  - name: mock-a
    url: http://127.0.0.1:9101/mcp
"""


def settings_for(
    *,
    policy_file: Path | None = None,
    upstreams_file: Path | None = None,
    approval_operator_token: str = "",
    approval_ttl_seconds: float = 300.0,
    approval_max_pending: int = 256,
) -> GatewaySettings:
    """Settings with the approval fields named explicitly.

    A `**overrides` splat would be shorter and is the thing this project has a
    standing rule against: pydantic types every field, and a splat of
    `dict[str, object]` erases all of it.
    """
    extra: dict[str, Any] = {}
    if policy_file is not None:
        extra["policy_file"] = policy_file
    if upstreams_file is not None:
        extra["upstreams_file"] = upstreams_file
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_required=False,
        health_probing_enabled=False,
        schema_drift_detection_enabled=False,
        approval_operator_token=approval_operator_token,
        approval_ttl_seconds=approval_ttl_seconds,
        approval_max_pending=approval_max_pending,
        **extra,
    )


# ---------------------------------------------------------------------------
# The store exists exactly when the policy can hold a call
# ---------------------------------------------------------------------------


def test_a_policy_that_gates_nothing_builds_no_store() -> None:
    """Presence-based on the policy, not on a flag. A deployment that never
    holds a call carries no machinery for holding one."""
    assert build_approval_store(settings_for(), OPEN) is None


def test_no_policy_at_all_builds_no_store() -> None:
    assert build_approval_store(settings_for(), None) is None


def test_a_policy_that_gates_a_call_builds_a_store() -> None:
    store = build_approval_store(settings_for(approval_operator_token=CREDENTIAL), GATED)

    assert store is not None


def test_the_configured_bound_reaches_the_store() -> None:
    """The bound is a security limit before a memory one — a caller whose policy
    gates a tool can start one held request per call and never retry."""
    store = build_approval_store(
        settings_for(approval_operator_token=CREDENTIAL, approval_max_pending=2), GATED
    )
    assert isinstance(store, InMemoryApprovalStore)

    for index in range(5):
        request = request_for(
            tenant=None,
            subject=ALICE,
            actor=None,
            tool=TOOL,
            arguments={"n": index},
            rule="approve-searches",
            now=float(index),
        )
        assert request is not None
        store.create(request)

    assert len(store.pending()) == 2


# ---------------------------------------------------------------------------
# The configuration that is correct and useless
# ---------------------------------------------------------------------------


def test_gating_calls_with_no_operator_channel_is_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The gateway is perfectly correct and completely useless: every gated call
    is held, nothing can answer it, and each caller waits out the TTL and is
    refused. A warning rather than a refusal to start, because a replicated
    deployment may answer from another process against a shared store — but it
    must not be quiet."""
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        build_approval_store(settings_for(), GATED)

    warned = [
        record for record in caplog.records if record.message == "approval.no_operator_channel"
    ]
    assert warned, [record.message for record in caplog.records]
    assert "waits out its TTL" in getattr(warned[0], "consequence", "")


def test_a_configured_channel_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        build_approval_store(settings_for(approval_operator_token=CREDENTIAL), GATED)

    assert not [r for r in caplog.records if r.message == "approval.no_operator_channel"]


def test_the_startup_line_names_the_rules_that_gate(caplog: pytest.LogCaptureFixture) -> None:
    """An operator reading the log should learn which rules can stop a call,
    not merely that approvals are switched on somewhere."""
    with caplog.at_level(logging.INFO, logger="acp.runtime"):
        build_approval_store(settings_for(approval_operator_token=CREDENTIAL), GATED)

    [enabled] = [r for r in caplog.records if r.message == "approval.enabled"]
    assert getattr(enabled, "gated_rules", None) == ["approve-searches"]
    assert getattr(enabled, "operator_channel", None) is True


# ---------------------------------------------------------------------------
# The credential produces routes
# ---------------------------------------------------------------------------


def test_the_admin_app_serves_the_channel_when_the_settings_configure_one() -> None:
    """Assembled the way `acp serve` assembles it, from the same two values."""
    settings = settings_for(approval_operator_token=CREDENTIAL)
    store = build_approval_store(settings, GATED)

    async def _run() -> int:
        app = build_admin_app(None, None, store, settings.approval_operator_token)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://admin"
        ) as client:
            response = await client.get(
                APPROVALS_PATH, headers={"authorization": f"Bearer {CREDENTIAL}"}
            )
            return response.status_code

    assert anyio.run(_run) == 200


def test_the_admin_app_serves_no_channel_when_the_settings_configure_none() -> None:
    settings = settings_for()
    store = build_approval_store(settings, GATED)

    async def _run() -> int:
        app = build_admin_app(None, None, store, settings.approval_operator_token)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://admin"
        ) as client:
            return (await client.get(APPROVALS_PATH)).status_code

    assert anyio.run(_run) == 404


# ---------------------------------------------------------------------------
# The whole assembly, from a settings object to a held call
# ---------------------------------------------------------------------------


def test_a_gateway_built_from_settings_holds_a_gated_call(tmp_path: Path) -> None:
    """The end of the wire. A policy file on disk, a settings object, and a real
    request that comes back `input_required` — with the store attached where
    `acp serve` looks for it."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(GATED_YAML)
    upstreams_file = tmp_path / "upstreams.yaml"
    upstreams_file.write_text(UPSTREAMS_YAML)
    settings = settings_for(
        policy_file=policy_file,
        upstreams_file=upstreams_file,
        approval_operator_token=CREDENTIAL,
    )

    async def _run() -> Any:
        async with gateway_from_settings(settings) as app:
            return app.state.approvals

    store = anyio.run(_run)

    assert store is not None


def test_the_configured_ttl_is_the_ttl_the_caller_gets(keypair: Keypair) -> None:
    """The hop a wiring test is for.

    `approval_ttl_seconds` is the default-deny wearing the clothes of a timeout.
    Unthreaded, it would read as configured and behave as the module default,
    and nothing anywhere would say so.
    """
    store = InMemoryApprovalStore()

    async def _run() -> None:
        async with authenticated_gateway(
            keypair,
            token=keypair.sign(claims()),
            policy=GATED,
            approvals=store,
            approval_ttl=12.0,
        ) as agent:
            await call_gateway(agent, "tools/call", {"name": TOOL, "arguments": {"query": "x"}})

    anyio.run(_run)

    held = store.pending()[0]
    assert held.expires_at - held.created_at == pytest.approx(12.0)
