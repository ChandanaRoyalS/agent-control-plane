"""The protected resource document, and the URL a client is told to fetch it from.

Two things are being pinned here and they fail differently. The document's
*shape* is a wire contract with clients nobody in this repository controls, so
it is asserted field by field rather than by round-tripping through the same
code that produced it. The metadata *URL* is arithmetic on a URI, and the
arithmetic is the RFC 8414 insertion rule rather than the OIDC append rule — a
distinction that costs nothing when the resource has no path and produces a
404 nobody can explain when it does.
"""

from __future__ import annotations

import json

import pytest

from acp.exceptions import ConfigurationError
from acp.identity.asgi import _bearer_token
from acp.identity.resource import (
    BEARER_METHODS,
    WELL_KNOWN_SEGMENT,
    ProtectedResource,
    protected_resource,
)

RESOURCE = "https://gw.corp.test/mcp"
ISSUER = "https://idp.corp.test/realms/acp"


# ---------------------------------------------------------------------------
# Where the document lives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("https://gw.corp.test", f"/{WELL_KNOWN_SEGMENT}"),
        ("https://gw.corp.test/", f"/{WELL_KNOWN_SEGMENT}"),
        ("https://gw.corp.test/mcp", f"/{WELL_KNOWN_SEGMENT}/mcp"),
        ("https://gw.corp.test/mcp/", f"/{WELL_KNOWN_SEGMENT}/mcp"),
        ("https://gw.corp.test/team/a/mcp", f"/{WELL_KNOWN_SEGMENT}/team/a/mcp"),
        ("https://gw.corp.test:8443/mcp", f"/{WELL_KNOWN_SEGMENT}/mcp"),
    ],
)
def test_the_well_known_segment_is_inserted_not_appended(resource: str, path: str) -> None:
    """RFC 9728 §3.1, and the same rule RFC 8414 uses for authorization servers.

    Appending — ``/mcp/.well-known/...`` — would put the document inside the
    resource's own path space, where it collides with the resource's routes and
    where a second protected resource on the same host cannot be told apart.
    """
    assert protected_resource(resource).metadata_path == path


def test_the_challenge_carries_an_absolute_url() -> None:
    """A path would require the client to reconstruct the origin it reached the
    gateway on, which behind a TLS-terminating proxy it cannot do reliably. The
    resource identifier is the one setting that knows the public origin."""
    assert (
        protected_resource("https://gw.corp.test:8443/mcp").metadata_url
        == f"https://gw.corp.test:8443/{WELL_KNOWN_SEGMENT}/mcp"
    )


def test_the_port_survives_and_the_scheme_survives() -> None:
    resource = protected_resource("http://localhost:8080/mcp")

    assert resource.metadata_url == f"http://localhost:8080/{WELL_KNOWN_SEGMENT}/mcp"


# ---------------------------------------------------------------------------
# What the document says
# ---------------------------------------------------------------------------


def test_the_document_names_the_resource_and_its_authorization_servers() -> None:
    document = protected_resource(
        RESOURCE, authorization_servers=[ISSUER, "https://idp.partner.test/"]
    ).document()

    assert document["resource"] == RESOURCE
    assert document["authorization_servers"] == [ISSUER, "https://idp.partner.test/"]


def test_absent_things_are_absent_rather_than_empty() -> None:
    """``"scopes_supported": []`` is a claim — that this resource has no scopes.
    Until Phase 3 defines them, saying nothing is the more accurate statement,
    and a client that reads an empty array may reasonably stop asking."""
    document = protected_resource(RESOURCE).document()

    assert "scopes_supported" not in document
    assert "resource_documentation" not in document
    assert "authorization_servers" not in document


def test_optional_fields_appear_when_they_have_content() -> None:
    document = protected_resource(
        RESOURCE,
        scopes_supported=["tools:read", "tools:call"],
        resource_documentation="https://gw.corp.test/docs",
        resource_name="corp gateway",
    ).document()

    assert document["scopes_supported"] == ["tools:read", "tools:call"]
    assert document["resource_documentation"] == "https://gw.corp.test/docs"
    assert document["resource_name"] == "corp gateway"


def test_the_document_is_json_and_stays_json() -> None:
    """It is rendered once at startup and served verbatim thereafter, so
    anything unserialisable in it is a 500 on the one endpoint a client hits
    before it has any other way to reach this gateway."""
    document = protected_resource(RESOURCE, authorization_servers=[ISSUER]).document()

    assert json.loads(json.dumps(document)) == document


def test_the_declared_bearer_methods_are_the_ones_actually_accepted() -> None:
    """The document is a description of this program, and a description that
    disagrees with the program is worse than none.

    RFC 6750 also defines ``?access_token=`` and a form field. Both write a
    credential into access logs, proxy request lines and ``Referer`` headers.
    ``_bearer_token`` reads the header and nothing else; this asserts the two
    statements are the same statement.
    """
    assert list(BEARER_METHODS) == ["header"]
    assert protected_resource(RESOURCE).document()["bearer_methods_supported"] == ["header"]

    # The claim, checked against the implementation rather than against itself.
    header_scope = {"headers": [(b"authorization", b"Bearer abc")]}
    query_scope = {"headers": [], "query_string": b"access_token=abc"}

    assert _bearer_token(header_scope) == "abc"
    assert _bearer_token(query_scope) is None


# ---------------------------------------------------------------------------
# Refused at startup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resource", "because"),
    [
        ("/mcp", "absolute"),
        ("gw.corp.test/mcp", "absolute"),
        ("", "absolute"),
        ("https://gw.corp.test/mcp#frag", "fragment"),
        ("https://gw.corp.test/mcp?tenant=a", "query string"),
        ("http://gw.corp.test/mcp", "https"),
    ],
)
def test_an_unusable_resource_identifier_stops_the_gateway(resource: str, because: str) -> None:
    """Fatal, and at startup. A bad identifier here surfaces three systems away
    as "authentication is broken": the client discovers, requests a token for
    the wrong audience, and is rejected by a gateway whose logs say only that a
    token had the wrong ``aud``."""
    with pytest.raises(ConfigurationError, match=because):
        protected_resource(resource)


def test_plain_http_is_allowed_on_loopback_and_only_there() -> None:
    """The same exception discovery makes, for the same reason: a Keycloak in
    ``docker compose`` is genuinely only reachable at ``http://localhost:8080``,
    and refusing it would mean nobody can run the demo. Everywhere else this
    document and the URL derived from it can be rewritten in transit, which
    points a client at an authorization server of the attacker's choosing."""
    assert protected_resource("http://localhost:8080/mcp").resource

    with pytest.raises(ConfigurationError, match="https"):
        protected_resource("http://gw.corp.test/mcp")


def test_the_identifier_is_validated_on_the_dataclass_not_just_the_helper() -> None:
    """Constructing ``ProtectedResource`` directly is the path a future caller
    takes without thinking about it, so the check lives in ``__post_init__``
    rather than in the convenience function."""
    with pytest.raises(ConfigurationError, match="fragment"):
        ProtectedResource(resource="https://gw.corp.test/mcp#x")
