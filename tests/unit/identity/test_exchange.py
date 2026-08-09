"""Token exchange: what goes to the authorization server, and what comes back.

The transport is a `MockTransport`, so every assertion here is about the request
this code *composes* — which is the part a specification defines and the part
that is wrong when an integration fails at 3am. Whether Keycloak agrees is a
different question, answered by `scripts/identity_smoke.py` against a real one.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CredentialExchangeError,
)
from acp.identity.exchange import (
    ACCESS_TOKEN_TYPE,
    GRANT_TYPE,
    ExchangedToken,
    TokenExchanger,
    require_token_endpoints,
)
from acp.identity.issuers import IssuerRegistration, IssuerRegistry
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy

ISSUER = "https://idp.corp.test/realms/acp"
PARTNER = "https://idp.partner.test/"
TOKEN_ENDPOINT = "https://idp.corp.test/realms/acp/protocol/openid-connect/token"
PARTNER_ENDPOINT = "https://idp.partner.test/token"

INBOUND = "inbound.subject.token"
MINTED = "minted.upstream.token"

CLIENT_ID = "acp-gateway"
CLIENT_SECRET = "dev-only-not-a-secret"


def registry(*, token_endpoint: str = TOKEN_ENDPOINT) -> IssuerRegistry:
    return IssuerRegistry(
        [
            IssuerRegistration(
                policy=TokenPolicy(issuer=ISSUER, audience="gw"),
                keys=JwksCache("https://idp.corp.test/keys"),
                token_endpoint=token_endpoint,
            ),
            IssuerRegistration(
                policy=TokenPolicy(issuer=PARTNER, audience="gw-partner"),
                keys=JwksCache("https://idp.partner.test/keys"),
                token_endpoint=PARTNER_ENDPOINT,
            ),
        ]
    )


class Server:
    """Records what the token endpoint was asked for, and answers however told."""

    def __init__(self, status: int = 200, payload: Any = None, body: str | None = None) -> None:
        self.status = status
        self.payload = (
            payload if payload is not None else {"access_token": MINTED, "expires_in": 300}
        )
        self.body = body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.body is not None:
            return httpx.Response(self.status, text=self.body)
        return httpx.Response(self.status, json=self.payload)

    @property
    def form(self) -> dict[str, str]:
        raw = self.requests[-1].content.decode()
        return dict(part.split("=", 1) for part in raw.split("&"))


def exchanger_for(server: Server) -> TokenExchanger:
    return TokenExchanger(
        registry(),
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
    )


def exchange(server: Server, *, issuer: str = ISSUER, audience: str = "upstream-a") -> Any:
    async def _run() -> Any:
        exchanger = exchanger_for(server)
        try:
            return await exchanger.exchange(subject_token=INBOUND, issuer=issuer, audience=audience)
        finally:
            await exchanger.aclose()

    return anyio.run(_run)


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


def test_the_request_is_an_rfc_8693_token_exchange() -> None:
    """Every parameter checked by name, because this is a wire contract with a
    server nobody here controls, and a silently wrong one produces `invalid_request`
    with no indication of which field."""
    server = Server()

    exchange(server)

    assert server.form["grant_type"] == GRANT_TYPE.replace(":", "%3A")
    assert server.form["subject_token"] == INBOUND
    assert server.form["subject_token_type"] == ACCESS_TOKEN_TYPE.replace(":", "%3A")
    assert server.form["requested_token_type"] == ACCESS_TOKEN_TYPE.replace(":", "%3A")
    assert server.form["audience"] == "upstream-a"


def test_the_gateway_authenticates_as_itself() -> None:
    """Two identities are in play and conflating them is the easy mistake. The
    subject token says who the work is *for*; the Basic credentials say who is
    *asking*. RFC 8693 requires the requesting client to authenticate, and
    Keycloak refuses the exchange outright from a public client."""
    server = Server()

    exchange(server)

    assert server.requests[-1].headers["authorization"].startswith("Basic ")


def test_the_exchange_goes_to_the_issuer_that_minted_the_subject_token() -> None:
    """The property ADR 0016 is about, at the one place in the codebase that
    sends a token *outward*. A single shared endpoint would mean presenting one
    authorization server's token to another's — the mix-up attack, reached by a
    convenience rather than by an attacker."""
    server = Server()

    exchange(server, issuer=ISSUER)
    assert str(server.requests[-1].url) == TOKEN_ENDPOINT

    exchange(server, issuer=PARTNER)
    assert str(server.requests[-1].url) == PARTNER_ENDPOINT


def test_an_unregistered_issuer_cannot_be_exchanged_for() -> None:
    """Selection is the registry's, so a token claiming an issuer nobody
    registered gets the same refusal here as it would at validation."""
    with pytest.raises(AuthenticationError):
        exchange(Server(), issuer="https://somebody.else/")


# ---------------------------------------------------------------------------
# The response
# ---------------------------------------------------------------------------


def test_a_successful_exchange_returns_a_scoped_credential() -> None:
    token = exchange(Server())

    assert token.access_token == MINTED
    assert token.audience == "upstream-a"
    assert token.issuer == ISSUER
    assert token.expires_at is not None


def test_a_credential_never_prints_itself() -> None:
    """The commonest way a secret reaches a log is a dataclass repr inside an
    exception message nobody meant to print. The default repr would have done
    exactly that, so this class has its own."""
    token = ExchangedToken(
        access_token="super-secret", audience="upstream-a", issuer=ISSUER, expires_at=1.0
    )

    assert "super-secret" not in repr(token)
    assert "super-secret" not in f"{token}"
    assert "upstream-a" in repr(token)


def test_expiry_is_judged_early_by_a_margin() -> None:
    """A token that is valid when the gateway checks it and expired when the
    upstream does fails *after* the side effect may already have happened."""
    token = ExchangedToken(access_token="x", audience="a", issuer=ISSUER, expires_at=1000.0)

    assert token.expired(now=1000.0) is True
    assert token.expired(now=980.0) is True, "inside the skew margin"
    assert token.expired(now=900.0) is False


def test_a_credential_with_no_stated_lifetime_never_reports_expired() -> None:
    """`expires_in` is optional in RFC 6749 §5.1. Guessing a lifetime would mean
    discarding a working credential on a schedule of our own invention."""
    token = ExchangedToken(access_token="x", audience="a", issuer=ISSUER, expires_at=None)

    assert token.expired(now=10**12) is False


# ---------------------------------------------------------------------------
# Refusal
# ---------------------------------------------------------------------------


def test_a_refused_exchange_is_not_worth_retrying() -> None:
    """A 400 is a configuration or entitlement problem: the audience does not
    exist, the client may not exchange, the subject token lacks the requester in
    its `aud`. All of them fail identically on the next attempt."""
    server = Server(status=400, payload={"error": "invalid_target"})

    with pytest.raises(CredentialExchangeError) as caught:
        exchange(server)

    assert caught.value.recoverable is False


def test_a_broken_authorization_server_is_worth_retrying() -> None:
    server = Server(status=503, payload={"error": "temporarily_unavailable"})

    with pytest.raises(CredentialExchangeError) as caught:
        exchange(server)

    assert caught.value.recoverable is True


def test_an_unreachable_authorization_server_is_worth_retrying() -> None:
    def refuse(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async def _run() -> None:
        exchanger = TokenExchanger(
            registry(),
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            http=httpx.AsyncClient(transport=httpx.MockTransport(refuse)),
        )
        try:
            await exchanger.exchange(subject_token=INBOUND, issuer=ISSUER, audience="a")
        finally:
            await exchanger.aclose()

    with pytest.raises(CredentialExchangeError) as caught:
        anyio.run(_run)

    assert caught.value.recoverable is True


def test_the_caller_is_never_told_why_the_server_refused() -> None:
    """`invalid_target` tells an agent nothing it can act on, and tells someone
    probing the gateway which audiences exist. The reason goes to the log; the
    caller gets one message."""
    server = Server(
        status=400,
        payload={"error": "invalid_target", "error_description": "no client acp-upstream-secret"},
    )

    with pytest.raises(CredentialExchangeError) as caught:
        exchange(server)

    assert "invalid_target" not in caught.value.message
    assert "acp-upstream-secret" not in caught.value.message


def test_a_response_without_a_token_is_a_failure_not_an_empty_credential() -> None:
    """200 with no `access_token` would otherwise produce `Bearer None` on the
    wire — an upstream rejecting a malformed header, three layers from the
    authorization server that caused it."""
    server = Server(payload={"issued_token_type": ACCESS_TOKEN_TYPE})

    with pytest.raises(CredentialExchangeError, match="no access_token"):
        exchange(server)


def test_a_non_json_response_is_a_failure() -> None:
    server = Server(body="<html>gateway timeout</html>")

    with pytest.raises(CredentialExchangeError, match="did not return JSON"):
        exchange(server)


def test_an_issuer_with_no_token_endpoint_refuses_rather_than_guessing() -> None:
    """A token endpoint derived from the issuer URL is a credential sent
    somewhere nobody chose."""
    server = Server()

    async def _run() -> None:
        exchanger = TokenExchanger(
            registry(token_endpoint=""),
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
        )
        try:
            await exchanger.exchange(subject_token=INBOUND, issuer=ISSUER, audience="a")
        finally:
            await exchanger.aclose()

    with pytest.raises(CredentialExchangeError, match="no token endpoint"):
        anyio.run(_run)
    assert server.requests == [], "nothing should have been sent anywhere"


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def test_startup_refuses_an_issuer_that_cannot_be_exchanged_against() -> None:
    """Fatal before a port is bound. With several issuers the one lacking an
    endpoint could be the tenant nobody tested, and the failure would arrive as
    a broken login for them alone."""
    with pytest.raises(ConfigurationError, match="no token endpoint is known"):
        require_token_endpoints(registry(token_endpoint=""))


def test_startup_is_satisfied_when_every_issuer_has_one() -> None:
    require_token_endpoints(registry())


def test_the_error_names_the_issuers_that_are_missing_one() -> None:
    """Read by whoever is working out why a deployment will not start."""
    with pytest.raises(ConfigurationError, match=ISSUER):
        require_token_endpoints(registry(token_endpoint=""))


def test_the_form_is_url_encoded_not_json() -> None:
    """RFC 6749 §3.2: the token endpoint takes `application/x-www-form-urlencoded`.
    A JSON body gets `invalid_request` from a compliant server and silence from
    a lenient one."""
    server = Server()

    exchange(server)

    request = server.requests[-1]
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    with pytest.raises(json.JSONDecodeError):
        json.loads(request.content)


# ---------------------------------------------------------------------------
# Resource indicators, and checking what was actually granted — task 28
# ---------------------------------------------------------------------------
#
# Measured, not assumed: Keycloak 26.7 accepts `resource` and discards it,
# including when it contradicts `audience` (ADR 0020). So these split into two
# groups — what the gateway *asks* for, and what it does with what it *gets*.
# Only the second group is a control.


def jwt_with(audience: list[str] | str) -> str:
    """A JWT-shaped string carrying an `aud`. Unsigned; nothing verifies it."""
    payload = base64.urlsafe_b64encode(json.dumps({"aud": audience}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


def exchanger_with_peers(server: Server, peers: list[str]) -> TokenExchanger:
    return TokenExchanger(
        registry(),
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        peer_audiences=peers,
        http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
    )


def exchange_with_peers(
    server: Server, peers: list[str], *, audience: str = "acp-upstream-mock-a"
) -> Any:
    async def _run() -> Any:
        exchanger = exchanger_with_peers(server, peers)
        try:
            return await exchanger.exchange(
                subject_token=INBOUND, issuer=ISSUER, audience=audience, resource=RESOURCE
            )
        finally:
            await exchanger.aclose()

    return anyio.run(_run)


RESOURCE = "https://mock-a.internal/mcp"
PEERS = ["acp-upstream-mock-a", "acp-upstream-mock-b"]


def test_the_resource_indicator_is_sent_when_configured() -> None:
    """RFC 8707's parameter, sent because it is the specified way to name a
    target and any conformant server acts on it. Sending it is *not* the
    control — see below — but a gateway that only works against the one server
    this project happens to run is not a gateway."""
    server = Server(payload={"access_token": jwt_with("acp-upstream-mock-a")})

    exchange_with_peers(server, PEERS)

    assert server.form["resource"] == RESOURCE.replace(":", "%3A").replace("/", "%2F")


def test_no_resource_is_sent_when_none_is_configured() -> None:
    """An empty parameter is not the same as an absent one. `resource=` would be
    a request to scope the token to nothing at all."""
    server = Server(payload={"access_token": jwt_with("acp-upstream-mock-a")})

    async def _run() -> Any:
        exchanger = exchanger_with_peers(server, PEERS)
        try:
            return await exchanger.exchange(
                subject_token=INBOUND, issuer=ISSUER, audience="acp-upstream-mock-a"
            )
        finally:
            await exchanger.aclose()

    anyio.run(_run)

    assert "resource" not in server.form


def test_a_credential_valid_at_two_upstreams_is_refused() -> None:
    """The confused-deputy condition, stated exactly.

    This is what a server that ignores the scope request actually returns —
    measured against Keycloak, an exchange it declines to narrow comes back
    carrying *every* audience the requester can reach, with no error. A gateway
    that sent `resource` and trusted it would hand mock-a a credential that also
    opens mock-b, and log a success.
    """
    server = Server(payload={"access_token": jwt_with(PEERS)})

    with pytest.raises(CredentialExchangeError, match="also valid at"):
        exchange_with_peers(server, PEERS)


def test_a_credential_for_the_wrong_target_is_refused() -> None:
    server = Server(payload={"access_token": jwt_with("acp-upstream-mock-b")})

    with pytest.raises(CredentialExchangeError, match="not for"):
        exchange_with_peers(server, PEERS)


def test_audiences_that_are_not_upstreams_are_ignored() -> None:
    """`account`, the requester's own client id, and whatever else a given server
    adds. The check is about *this gateway's estate*, not about tidiness — which
    is what stops it having false positives to tune away, and therefore what
    stops it being switched off."""
    server = Server(
        payload={"access_token": jwt_with(["acp-upstream-mock-a", "account", "acp-gateway"])}
    )

    token = exchange_with_peers(server, PEERS)

    assert token.audience == "acp-upstream-mock-a"


def test_a_single_upstream_deployment_has_nothing_to_cross() -> None:
    """An empty peer set is not a failure — it is a gateway with one upstream,
    where a credential cannot be valid at a neighbour it does not have."""
    server = Server(payload={"access_token": jwt_with(["acp-upstream-mock-a", "anything-else"])})

    token = exchange_with_peers(server, [])

    assert token.audience == "acp-upstream-mock-a"


def test_an_opaque_credential_cannot_be_checked_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Refusing would rule out every authorization server that issues opaque
    tokens, for a property the gateway cannot observe either way. Proceeding
    silently would report a check that never ran. So: proceed, and say so."""
    server = Server(payload={"access_token": "an-opaque-reference-token"})

    with caplog.at_level(logging.WARNING, logger="acp.identity.exchange"):
        token = exchange_with_peers(server, PEERS)

    assert token.access_token == "an-opaque-reference-token"
    assert any(r.message == "auth.scope_unverifiable" for r in caplog.records)


def test_a_credential_with_no_audience_at_all_is_refused() -> None:
    """Readable, and scoped to nothing. Distinct from unreadable: one is a token
    this gateway cannot judge, the other is one it has judged and rejected."""
    server = Server(payload={"access_token": jwt_with([])})

    with pytest.raises(CredentialExchangeError, match="not for"):
        exchange_with_peers(server, PEERS)
