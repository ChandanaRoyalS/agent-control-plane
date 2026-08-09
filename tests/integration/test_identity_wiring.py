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

Task 24 adds the same question one layer out: whether the published protected
resource document actually names the servers the registry holds, rather than a
second list that has to be kept in step with it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

import anyio
import pytest

from acp.config import GatewaySettings
from acp.exceptions import ConfigurationError
from acp.identity import ProviderMetadata, TokenValidator
from acp.runtime import build_protected_resource, build_token_validator

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
    resource: str = "",
    issuers_file: Path | None = None,
    required: bool = False,
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
        auth_resource=resource,
        auth_issuers_file=issuers_file,
        # False unless a test says otherwise. `auth_required` is an assertion
        # that a provider is configured, and most cases here are *about* what
        # happens when one is or is not — so the assertion would be answering
        # the question under test.
        auth_required=required,
    )


class FakeDiscovery:
    """Stands in for the authorization server's metadata endpoint.

    The signature mirrors `discover` exactly, keyword arguments included. That
    is not tidiness: a monkeypatched callable which accepts *less* than the real
    one fails only when the caller passes the argument it is missing, so adding
    a parameter to `discover` breaks every test that patches it — at the call
    site, with a `TypeError` about a fake. Which is precisely what `insecure_hosts`
    did in task 26.
    """

    def __init__(self, jwks_uri: str = DISCOVERED) -> None:
        self.jwks_uri = jwks_uri
        self.asked: list[str] = []
        self.insecure_hosts: list[str] = []

    async def __call__(
        self,
        issuer: str,
        *,
        request_timeout: float = 5.0,
        insecure_hosts: Iterable[str] = (),
    ) -> ProviderMetadata:
        self.asked.append(issuer)
        self.insecure_hosts = list(insecure_hosts)
        return ProviderMetadata(issuer=issuer, jwks_uri=self.jwks_uri, source="fake")


class FailingDiscovery:
    async def __call__(
        self,
        issuer: str,
        *,
        request_timeout: float = 5.0,
        insecure_hosts: Iterable[str] = (),
    ) -> ProviderMetadata:
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


# ---------------------------------------------------------------------------
# Protected resource metadata — task 24
# ---------------------------------------------------------------------------

RESOURCE = "https://gw.corp.test/mcp"


def built(monkeypatch: pytest.MonkeyPatch, config: GatewaySettings) -> TokenValidator | None:
    """No `**dict` splat — see `settings` above for why this file spells every
    argument out."""
    install(monkeypatch, FakeDiscovery())
    validator: TokenValidator | None = anyio.run(build_token_validator, config)
    return validator


def test_no_validator_means_no_document() -> None:
    """Config already refuses a resource identifier with no issuer, so this is
    the plain unauthenticated case and there is nothing to publish."""
    assert build_protected_resource(settings(), None) is None


def test_the_authorization_servers_are_the_registry_not_a_second_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The one property that matters here. Two lists that had to be kept in step
    eventually would not be, and the failure lands on the client: sent to an
    authorization server this gateway does not trust, it sees its own perfectly
    good token inexplicably rejected."""
    install(monkeypatch, FakeDiscovery())
    path = tmp_path / "issuers.yaml"
    path.write_text(
        f"""
issuers:
  - issuer: {ISSUER}
    audience: {RESOURCE}
  - issuer: {PARTNER}
    audience: {RESOURCE}
    jwks_url: {PARTNER}keys
""",
        encoding="utf-8",
    )
    config = settings(issuers_file=path, resource=RESOURCE)
    validator = anyio.run(build_token_validator, config)

    resource = build_protected_resource(config, validator)

    assert resource is not None
    assert validator is not None
    assert list(resource.authorization_servers) == validator.issuers.issuers


def test_a_gateway_that_publishes_nothing_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Not fatal — authentication is unaffected — but not silent either. "No
    client can discover us" is a state somebody should have chosen rather than
    inherited from an unset variable."""
    config = settings(issuer=ISSUER, audience=AUDIENCE)
    validator = built(monkeypatch, config)

    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        assert build_protected_resource(config, validator) is None

    assert any(r.message == "auth.resource_metadata_disabled" for r in caplog.records)


def test_a_resource_that_no_issuer_will_mint_for_is_a_warning_not_a_refusal(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Every step of the discovery chain works and the last one fails: the
    client reads the document, asks for `resource=<this>`, gets a token whose
    `aud` is `<this>`, and the gateway rejects it for the wrong audience.

    A warning rather than a refusal because plenty of authorization servers
    identify a resource by an opaque client ID rather than by its URL, and that
    is a legitimate deployment — it just means the client has to be told, which
    is the thing this document was meant to stop being necessary.
    """
    config = settings(issuer=ISSUER, audience=AUDIENCE, resource=RESOURCE)
    validator = built(monkeypatch, config)

    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        resource = build_protected_resource(config, validator)

    assert resource is not None, "a mismatch must not suppress the document"
    assert any(r.message == "auth.resource_audience_mismatch" for r in caplog.records)


def test_a_resource_matching_the_audience_warns_about_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The intended shape: the resource identifier *is* the audience, so a
    client that follows the metadata ends up holding exactly the token this
    gateway demands with nothing hardcoded anywhere."""
    config = settings(issuer=ISSUER, audience=RESOURCE, resource=RESOURCE)
    validator = built(monkeypatch, config)

    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        resource = build_protected_resource(config, validator)

    assert resource is not None
    assert resource.metadata_url == "https://gw.corp.test/.well-known/oauth-protected-resource/mcp"
    assert not [r for r in caplog.records if r.message.startswith("auth.resource")]


# ---------------------------------------------------------------------------
# Refusing to serve unauthenticated — task 26
# ---------------------------------------------------------------------------


def test_asserting_a_provider_and_not_configuring_one_is_fatal() -> None:
    """`ACP_AUTH_REQUIRED` is an assertion, not a switch.

    It cannot turn authentication on — only configuring a provider does that.
    What it says is "a provider is configured here", and a deployment where that
    is false has failed rather than entered a different mode. Fatal at startup,
    before a port is bound and before an upstream pool is opened.
    """
    with pytest.raises(ConfigurationError, match="every request as `anonymous`"):
        anyio.run(build_token_validator, settings(required=True))


def test_the_assertion_is_not_made_when_a_provider_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch, FakeDiscovery())

    validator = anyio.run(
        build_token_validator, settings(issuer=ISSUER, audience=AUDIENCE, required=True)
    )

    assert validator is not None


def test_unauthenticated_stays_a_supported_mode() -> None:
    """It has to. It is how every task before 26 ran, it is what a mocks-only
    stack still does, and a gateway that could not start without an identity
    provider it was never told about would be a strange way to run
    unauthenticated. The cost is one line somebody wrote on purpose."""
    assert anyio.run(build_token_validator, settings(required=False)) is None


def test_the_insecure_host_list_reaches_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wiring that makes the Compose demo work at all.

    `discover` refuses a plain-HTTP issuer unless its host is named, and the
    naming happens in settings — so a list that stops anywhere between the two
    produces a gateway that cannot start against its own committed Keycloak.
    Asserting the *argument arrives* rather than the outcome, because the
    outcome is `discovery`'s own test's job.
    """
    fake = FakeDiscovery()
    install(monkeypatch, fake)

    anyio.run(
        build_token_validator,
        GatewaySettings(  # type: ignore[call-arg]
            _env_file=None,
            auth_issuer=ISSUER,
            auth_audience=AUDIENCE,
            auth_insecure_issuer_hosts=["keycloak"],
        ),
    )

    assert fake.insecure_hosts == ["keycloak"]
