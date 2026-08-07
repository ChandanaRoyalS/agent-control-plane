"""Tests for process lifecycle: building the gateway and tearing it down.

The property under test is that connection pools are always closed — on the
happy path, on an exception inside the context, and even when one upstream's
close fails. A leaked pool is a leaked socket, and a gateway restarted a few
hundred times in a deploy loop would exhaust the host.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import anyio
import pytest

from acp.config import GatewaySettings
from acp.exceptions import ConfigurationError
from acp.identity import DEFAULT_ALGORITHMS
from acp.runtime import (
    build_drift_detector,
    build_token_validator,
    gateway_from_configs,
    gateway_from_settings,
)
from acp.schema import SchemaSnapshot
from acp.upstream import UpstreamConfig
from acp.upstream.models import ListToolsResult

pytestmark = pytest.mark.integration

CONFIGS = [
    UpstreamConfig(name="mock-a", url="http://127.0.0.1:9101/mcp"),
    UpstreamConfig(name="mock-b", url="http://127.0.0.1:9102/mcp"),
]


def test_the_gateway_builds_and_tears_down_cleanly() -> None:
    async def _run() -> Any:
        async with gateway_from_configs(CONFIGS) as app:
            return app

    assert anyio.run(_run) is not None


def test_pools_are_closed_when_the_body_raises() -> None:
    """A failure while serving must not leak sockets.

    `finally` rather than a happy-path close is what makes this hold, and it is
    the difference between a crash and a crash that also exhausts the host.
    """

    class BoomError(Exception):
        pass

    async def _run() -> None:
        async with gateway_from_configs(CONFIGS):
            raise BoomError

    with pytest.raises(BoomError):
        anyio.run(_run)


def test_an_empty_upstream_list_still_builds() -> None:
    """Bringing the gateway up before its upstreams exist is legitimate."""

    async def _run() -> Any:
        async with gateway_from_configs([]) as app:
            return app

    assert anyio.run(_run) is not None


def test_settings_path_validates_before_opening_connections(tmp_path: Path) -> None:
    """A bad config must fail with no side effects at all.

    Reading and validating upstreams *before* connecting means a typo in the
    YAML cannot leave half-open pools behind.
    """
    bad = tmp_path / "upstreams.yaml"
    bad.write_text("upstreams:\n  - name: BAD_NAME\n    url: http://x/mcp\n", encoding="utf-8")
    settings = GatewaySettings(upstreams_file=bad, _env_file=None)  # type: ignore[call-arg]

    async def _run() -> None:
        async with gateway_from_settings(settings):
            pass

    with pytest.raises(ConfigurationError, match="BAD_NAME"):
        anyio.run(_run)


# ---------------------------------------------------------------------------
# Schema drift wiring (task 20)
# ---------------------------------------------------------------------------


def test_a_missing_baseline_does_not_stop_the_gateway(tmp_path: Path) -> None:
    """Every new deployment starts unbaselined. Refusing to serve over it would
    be absurd; saying so once per upstream is the whole response."""
    detector = build_drift_detector(tmp_path / "absent.json", ["mock-a"])

    assert detector.has_baseline is False


def test_a_corrupt_baseline_is_loud_but_not_fatal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The only place in this project where a bad file on disk does not stop
    the process, and the exception is deliberate. Configuration failures are
    fatal because a gateway that starts with a broken policy has already failed
    open. A schema baseline is a *monitor*, and a monitor that can prevent the
    gateway from serving is a larger risk than the one it exists to reduce.
    """
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{not json", encoding="utf-8")

    with caplog.at_level(logging.ERROR, logger="acp.runtime"):
        detector = build_drift_detector(baseline, ["mock-a"])

    assert detector.has_baseline is False
    assert any(r.message == "schema.baseline_unreadable" for r in caplog.records)


def test_a_valid_baseline_is_loaded(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    SchemaSnapshot.from_catalogues({"mock-a": ListToolsResult()}).save(baseline)

    assert build_drift_detector(baseline, ["mock-a"]).has_baseline is True


def test_asking_for_drift_detection_without_probing_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Detection rides on the prober's fetch, so this combination cannot do
    what it says. Silently detecting nothing would be the worse outcome."""

    async def _run() -> None:
        with caplog.at_level(logging.WARNING, logger="acp.runtime"):
            async with gateway_from_configs([], probe_health=False, detect_drift=True) as app:
                assert app.state.schema_drift is None

    anyio.run(_run)

    assert any(r.message == "schema.drift_detection_inert" for r in caplog.records)


# ---------------------------------------------------------------------------
# Identity wiring (task 22)
# ---------------------------------------------------------------------------

ISSUER = "https://idp.test/realms/acp"
AUDIENCE = "agent-control-plane"
JWKS_URL = "https://idp.test/realms/acp/certs"


def identity_settings(algorithms: list[str] | None = None) -> GatewaySettings:
    """Written out rather than splatted from a dict.

    `**{"auth_issuer": ...}` is a `dict[str, str]`, and mypy cannot check kwargs
    unpacked from one against a model whose fields are variously `int`, `bool`,
    `Path` and `list[str]` — so it rejects every one of them. Explicit arguments
    are longer and are what actually type-checks.
    """
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_issuer=ISSUER,
        auth_audience=AUDIENCE,
        auth_jwks_url=JWKS_URL,
        auth_algorithms=list(algorithms if algorithms is not None else DEFAULT_ALGORITHMS),
    )


def test_no_provider_configured_builds_no_validator() -> None:
    """`None` here is what makes the gateway run unauthenticated, which is how
    every task before this one behaved and has to keep working."""
    settings = GatewaySettings(_env_file=None)  # type: ignore[call-arg]

    assert anyio.run(build_token_validator, settings) is None


def test_a_configured_provider_builds_a_validator() -> None:
    validator = anyio.run(build_token_validator, identity_settings())

    assert validator is not None
    # One registration, and everything about that authorization server lives
    # inside it — see ADR 0016 on why issuer, audience and key set are not
    # separately addressable.
    assert validator.issuers.issuers == [ISSUER]
    registration = validator.issuers.registration_for(ISSUER)
    assert registration.audience == AUDIENCE
    assert registration.keys.url == JWKS_URL


def test_a_symmetric_algorithm_stops_the_gateway_starting() -> None:
    """Before a port is bound, rather than on the first request that exploits
    it. A JWKS publishes public keys, so accepting HS256 means accepting tokens
    an attacker can forge from published material — a misconfiguration that
    fails *open* has to be impossible to run, not merely unlikely to be
    written."""
    settings = identity_settings(algorithms=["RS256", "HS256"])

    with pytest.raises(ConfigurationError, match="symmetric"):
        anyio.run(build_token_validator, settings)


def test_an_unauthenticated_gateway_says_so_at_startup(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Half of what makes unauthenticated mode acceptable at all. The other half
    is `principal: anonymous` on every request line — together they mean nobody
    can read a log and fail to notice that nothing is being authenticated."""

    async def _run() -> None:
        with caplog.at_level(logging.WARNING, logger="acp.runtime"):
            async with gateway_from_configs([], validator=None):
                pass

    anyio.run(_run)

    assert any(r.message == "auth.disabled" for r in caplog.records)
