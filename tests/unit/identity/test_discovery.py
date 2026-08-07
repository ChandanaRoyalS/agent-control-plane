"""Unit tests for authorization server metadata discovery.

The check worth having is `test_metadata_naming_a_different_issuer_is_refused`.
Everything else is the machinery that gets us to the point where that check can
run.

Discovery is not here for convenience. Configuring a JWKS URL by hand is easy;
what it cannot do is *prove* that the key set belongs to the issuer you claim to
trust. RFC 8414 §3.3 is that proof, in one sentence: the metadata must name the
same issuer the document was fetched for.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import ConfigurationError
from acp.identity.discovery import OAUTH_SEGMENT, OIDC_SEGMENT, candidate_urls, discover

ISSUER = "https://idp.test/realms/acp"
JWKS = "https://idp.test/realms/acp/protocol/openid-connect/certs"


class Provider:
    """An authorization server that serves metadata at chosen paths."""

    def __init__(self, documents: dict[str, Any] | None = None) -> None:
        self.documents = documents or {}
        self.requested: list[str] = []

    def client(self) -> httpx.AsyncClient:
        def handle(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            self.requested.append(url)
            document = self.documents.get(url)
            if document is None:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json=document)

        return httpx.AsyncClient(transport=httpx.MockTransport(handle))


def metadata(issuer: str = ISSUER, jwks_uri: str = JWKS, **extra: Any) -> dict[str, Any]:
    return {"issuer": issuer, "jwks_uri": jwks_uri, **extra}


def run(fn: Any) -> Any:
    return anyio.run(fn)


def fetch(provider: Provider, issuer: str = ISSUER) -> Any:
    return run(lambda: discover(issuer, client=provider.client()))


# ---------------------------------------------------------------------------
# The binding check
# ---------------------------------------------------------------------------


def test_metadata_naming_a_different_issuer_is_refused() -> None:
    """RFC 8414 §3.3. The document was fetched from a location derived from one
    issuer and claims to belong to another — which is a key set that cannot be
    attributed to the server being trusted, and therefore keys this gateway must
    not verify with."""
    oauth_url, _ = candidate_urls(ISSUER)
    provider = Provider({oauth_url: metadata(issuer="https://idp.attacker.test/")})

    with pytest.raises(ConfigurationError, match="RFC 8414"):
        fetch(provider)


def test_a_mismatch_is_fatal_rather_than_a_reason_to_try_the_next_url() -> None:
    """A server that answered and named somebody else has not failed to answer.
    Falling through to the other well-known path would be looking for a server
    willing to agree with us, which is not verification."""
    oauth_url, oidc_url = candidate_urls(ISSUER)
    provider = Provider(
        {oauth_url: metadata(issuer="https://idp.attacker.test/"), oidc_url: metadata()}
    )

    with pytest.raises(ConfigurationError):
        fetch(provider)

    assert oidc_url not in provider.requested, "kept looking after a server contradicted itself"


def test_a_trailing_slash_difference_is_still_a_mismatch_and_says_so() -> None:
    """Identical means identical — normalising here would mean this gateway's
    notion of "the same server" differed from the specification's. But it is by
    far the commonest way to hit this, and the two strings look the same in a
    terminal, so the message names the cause."""
    oauth_url, _ = candidate_urls(ISSUER)
    provider = Provider({oauth_url: metadata(issuer=ISSUER + "/")})

    with pytest.raises(ConfigurationError, match="trailing slash"):
        fetch(provider)


# ---------------------------------------------------------------------------
# The two URL forms
# ---------------------------------------------------------------------------


def test_rfc_8414_inserts_the_segment_before_the_path() -> None:
    """`https://host/realms/acp` becomes
    `https://host/.well-known/oauth-authorization-server/realms/acp` — inserted,
    not appended. Getting this backwards is the single most common reason
    discovery "does not work" against a server that implements RFC 8414."""
    oauth_url, _ = candidate_urls(ISSUER)

    assert oauth_url == f"https://idp.test/{OAUTH_SEGMENT}/realms/acp"


def test_openid_connect_appends_it_instead() -> None:
    _, oidc_url = candidate_urls(ISSUER)

    assert oidc_url == f"https://idp.test/realms/acp/{OIDC_SEGMENT}"


def test_the_oauth_form_is_tried_first() -> None:
    oauth_url, oidc_url = candidate_urls(ISSUER)
    provider = Provider({oauth_url: metadata(), oidc_url: metadata()})

    result = fetch(provider)

    assert provider.requested == [oauth_url]
    assert result.source == oauth_url


def test_the_openid_form_is_the_fallback() -> None:
    """Many servers implement only OIDC Discovery. A client that knows one form
    fails against half the world for a reason that looks like a network
    problem."""
    oauth_url, oidc_url = candidate_urls(ISSUER)
    provider = Provider({oidc_url: metadata()})

    result = fetch(provider)

    assert provider.requested == [oauth_url, oidc_url]
    assert result.source == oidc_url
    assert result.jwks_uri == JWKS


def test_an_issuer_with_no_path_still_produces_both_forms() -> None:
    oauth_url, oidc_url = candidate_urls("https://idp.test")

    assert oauth_url == f"https://idp.test/{OAUTH_SEGMENT}"
    assert oidc_url == f"https://idp.test/{OIDC_SEGMENT}"


def test_a_trailing_slash_on_the_issuer_does_not_double_up() -> None:
    oauth_url, oidc_url = candidate_urls("https://idp.test/realms/acp/")

    assert "//" not in oauth_url.removeprefix("https://")
    assert "//" not in oidc_url.removeprefix("https://")


# ---------------------------------------------------------------------------
# Refusing issuers that cannot be used safely
# ---------------------------------------------------------------------------


def test_a_plain_http_issuer_is_refused() -> None:
    """Metadata fetched over HTTP can be rewritten in transit, and this document
    decides which signing keys the gateway trusts."""
    with pytest.raises(ConfigurationError, match="https"):
        run(lambda: discover("http://idp.test/realms/acp", client=Provider().client()))


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_loopback_may_use_plain_http(host: str) -> None:
    """A Keycloak in `docker compose` on a laptop is genuinely reachable only at
    `http://localhost:8080`, and refusing it would mean nobody can run the
    demo."""
    issuer = f"http://{host}:8080/realms/acp"
    oauth_url, _ = candidate_urls(issuer)
    provider = Provider({oauth_url: metadata(issuer=issuer)})

    assert fetch(provider, issuer).issuer == issuer


@pytest.mark.parametrize(
    "issuer",
    [
        "https://idp.test/realms?tenant=a",
        "https://idp.test/realms#fragment",
    ],
)
def test_an_issuer_with_a_query_or_fragment_is_refused(issuer: str) -> None:
    """RFC 8414 §2. Two spellings of the same server would compare unequal, and
    equality is the entire mechanism."""
    with pytest.raises(ConfigurationError, match="query string or fragment"):
        run(lambda: discover(issuer, client=Provider().client()))


def test_a_relative_issuer_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="absolute"):
        run(lambda: discover("realms/acp", client=Provider().client()))


# ---------------------------------------------------------------------------
# When the server is unhelpful
# ---------------------------------------------------------------------------


def test_a_server_publishing_nothing_is_a_startup_failure() -> None:
    """Every failure here is fatal, because this runs before the port is bound
    and a gateway that starts with an unverified idea of which keys to trust has
    already lost the property discovery provides."""
    with pytest.raises(ConfigurationError, match="could not discover"):
        fetch(Provider())


def test_the_failure_names_what_was_tried() -> None:
    """Read by whoever is working out why nothing can authenticate. "Discovery
    failed" without the URLs is not enough to act on."""
    oauth_url, oidc_url = candidate_urls(ISSUER)

    with pytest.raises(ConfigurationError) as caught:
        fetch(Provider())

    assert oauth_url in caught.value.message
    assert oidc_url in caught.value.message


def test_metadata_without_a_jwks_uri_is_refused() -> None:
    oauth_url, _ = candidate_urls(ISSUER)
    provider = Provider({oauth_url: {"issuer": ISSUER}})

    with pytest.raises(ConfigurationError, match="jwks_uri"):
        fetch(provider)


def test_a_document_that_is_not_an_object_is_skipped() -> None:
    oauth_url, oidc_url = candidate_urls(ISSUER)
    provider = Provider({oauth_url: ["not", "an", "object"], oidc_url: metadata()})

    assert fetch(provider).source == oidc_url
