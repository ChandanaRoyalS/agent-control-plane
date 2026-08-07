"""Does the issuer binding actually get wired in?

`discover` has nineteen tests and `IssuerRegistry` has fifteen. Neither says
anything about whether the gateway *calls* them, and "the security control is
implemented but not reachable" is a real and quiet way to fail — the same gap
that left `build_token_validator` untested in task 22 behind a 93% coverage
number.

So this file asserts the wiring: that a missing `jwks_url` is discovered rather
than ignored, that an explicit one skips discovery and says so, that a file of
several issuers becomes several registrations, and that a server contradicting
its own identity stops the process instead of the first request.
"""

from __future__ import annotations

import logging
from pathlib import Path

import anyio
import pytest

from acp.config import GatewaySettings
from acp.exceptions import ConfigurationError
from acp.identity import ProviderMetadata
from acp.runtime import build_token_validator

pytestmark = pytest.mark.integration

ISSUER = "https://idp.corp.test/realms/acp"
PARTNER = "https://idp.partner.test/"
AUDIENCE = "agent-control-plane"
DISCOVERED = "https://idp.corp.test/realms/acp/protocol/openid-connect/certs"
EXPLICIT = "https://idp.corp.test/keys"


def settings(
    *,
    issuer: str = "",
    audience: str = "",
    jwks_url: str = "",
    issuers_file: Path | None = None,
) -> GatewaySettings:
    """Explicit keyword arguments, never a `**dict` splat.

    mypy cannot check kwargs unpacked from a `dict[str, str]` against a model
    whose fields are variously `int`, `bool`, `Path` and `list[str]`, so it
    rejects all of them — and this module is one the archive-building sandbox
    cannot type-check, because importing it pulls in the MCP SDK.
    """
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_issuer=issuer,
        auth_audience=audience,
        auth_jwks_url=jwks_url,
        auth_issuers_file=issuers_file,
    )


class FakeDiscovery:
    """Stands in for the authorization server's metadata endpoint."""

    def __init__(self, jwks_uri: str = DISCOVERED) -> None:
        self.jwks_uri = jwks_uri
        self.asked: list[str] = []

    async def __call__(self, issuer: str, *, request_timeout: float = 5.0) -> ProviderMetadata:
        self.asked.append(issuer)
        return ProviderMetadata(issuer=issuer, jwks_uri=self.jwks_uri, source="fake")


class FailingDiscovery:
    async def __call__(self, issuer: str, *, request_timeout: float = 5.0) -> ProviderMetadata:
        msg = f"metadata at {issuer} declares issuer 'https://somebody.else/'"
        raise ConfigurationError(msg)


def install(monkeypatch: pytest.MonkeyPatch, fake: object) -> None:
    monkeypatch.setattr("acp.runtime.discover", fake)


# ---------------------------------------------------------------------------
# Discovery is reached
# ---------------------------------------------------------------------------


def test_a_missing_jwks_url_is_discovered(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default path, and the one that carries the RFC 8414 §3.3 check.
    Leaving `jwks_url` unset is what makes the binding between an issuer and its
    keys verified rather than asserted."""
    fake = FakeDiscovery()
    install(monkeypatch, fake)

    validator = anyio.run(build_token_validator, settings(issuer=ISSUER, audience=AUDIENCE))

    assert fake.asked == [ISSUER], "discovery was not reached"
    assert validator is not None
    assert validator.issuers.registration_for(ISSUER).keys.url == DISCOVERED


def test_an_explicit_jwks_url_skips_discovery_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Permitted, because some authorization servers publish no metadata at all
    and refusing them would be a purity the deployment cannot act on. Logged,
    because skipping a check should be a decision somebody made rather than one
    inherited from a config file they never read."""
    fake = FakeDiscovery()
    install(monkeypatch, fake)

    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        validator = anyio.run(
            build_token_validator,
            settings(issuer=ISSUER, audience=AUDIENCE, jwks_url=EXPLICIT),
        )

    assert fake.asked == [], "discovery ran even though a URL was configured"
    assert validator is not None
    assert validator.issuers.registration_for(ISSUER).keys.url == EXPLICIT
    assert any(r.message == "auth.jwks_url_unverified" for r in caplog.records)


def test_a_server_that_contradicts_itself_stops_the_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fatal, and at startup rather than on the first request. A gateway that
    begins serving with an unverified idea of which keys to trust has already
    lost the property discovery provides."""
    install(monkeypatch, FailingDiscovery())

    with pytest.raises(ConfigurationError, match="declares issuer"):
        anyio.run(build_token_validator, settings(issuer=ISSUER, audience=AUDIENCE))


# ---------------------------------------------------------------------------
# Several issuers
# ---------------------------------------------------------------------------


def test_an_issuers_file_becomes_one_registration_per_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """And each keeps its own audience and key set — the property ADR 0016 is
    about, checked here at the level where the configuration actually turns into
    registrations."""
    fake = FakeDiscovery()
    install(monkeypatch, fake)

    path = tmp_path / "issuers.yaml"
    path.write_text(
        f"""
issuers:
  - issuer: {ISSUER}
    audience: {AUDIENCE}
  - issuer: {PARTNER}
    audience: {AUDIENCE}-partner
    jwks_url: {PARTNER}keys
""",
        encoding="utf-8",
    )

    validator = anyio.run(build_token_validator, settings(issuers_file=path))

    assert validator is not None
    assert validator.issuers.issuers == sorted([ISSUER, PARTNER])
    # Only the entry without a URL asked the network anything.
    assert fake.asked == [ISSUER]

    corporate = validator.issuers.registration_for(ISSUER)
    partner = validator.issuers.registration_for(PARTNER)

    assert corporate.audience == AUDIENCE
    assert partner.audience == f"{AUDIENCE}-partner"
    assert corporate.keys.url == DISCOVERED
    assert partner.keys.url == f"{PARTNER}keys"


def test_no_identity_configuration_reaches_no_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unauthenticated mode must not depend on an identity provider being
    reachable — a gateway that cannot start without one it was never told about
    would be a strange way to run unauthenticated."""
    fake = FakeDiscovery()
    install(monkeypatch, fake)

    assert anyio.run(build_token_validator, settings()) is None
    assert fake.asked == []
