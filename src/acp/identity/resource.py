"""Telling a client which authorization server to go and ask — RFC 9728.

Task 23 made the gateway trust several authorization servers safely. It said
nothing at all about how a *client* is supposed to find out which one to get a
token from, and the answer today is "somebody configured it by hand". That is
fine for one agent and one gateway. It stops being fine the moment an agent
platform connects to servers it did not know about at build time, which is the
entire premise of MCP.

RFC 9728 is the small specification that closes it, and the mechanism is worth
stating plainly because it inverts the usual direction of discovery:

1. A client makes a request with no token and gets ``401`` with
   ``WWW-Authenticate: Bearer resource_metadata="<url>"``.
2. It fetches that URL and reads ``authorization_servers``.
3. It runs RFC 8414 discovery against one of *those* — task 23's code, from the
   other side of the wire — and now knows where to authenticate.

The client is told where to go by the resource it was trying to reach, rather
than being configured with a list of identity providers it has to keep in sync.

**This document is unauthenticated, necessarily and deliberately.** It is the
answer to "how do I authenticate", so requiring authentication to read it is a
loop with no entry point. What makes that acceptable is that the exemption is
*derived* rather than configured: ``AuthenticationMiddleware`` takes the
``ProtectedResource`` itself and exempts exactly ``metadata_path`` and nothing
else. There is no allow-list to add a second entry to, so a future path cannot
be made public by editing config, and the one public path is the one whose whole
purpose is to be readable by an unauthenticated caller.

**It is also reconnaissance, and that is a real cost paid on purpose.** This
names the organisation's authorization servers to anybody who asks. ADR 0010
made the opposite call for the metrics endpoint and put it on a loopback-only
listener. The difference is who the audience is: a scrape endpoint enumerating
upstreams and failing dependencies has no legitimate anonymous reader, and this
has almost nothing *but* anonymous readers — a client that could already
authenticate does not need it. An authorization server's own metadata is public
by the same reasoning.

**The resource identifier is the same string twice.** It is what this document
declares under ``resource``, and it is what a client passes as RFC 8707's
``resource`` parameter when asking for a token — which is what the authorization
server puts in ``aud``, which is what task 22 checks. So a client that follows
this chain from a 401 to a token ends up holding exactly the audience this
gateway demands, with nothing hardcoded anywhere along the way. That chain is
also why ``runtime`` warns when the configured resource identifier is not among
the audiences any registered issuer is expected to mint: the discovery would
work perfectly and the last step would fail.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from acp.exceptions import ConfigurationError
from acp.identity.discovery import LOOPBACK_HOSTS

WELL_KNOWN_SEGMENT = ".well-known/oauth-protected-resource"
"""RFC 9728 §3.1 — *inserted* between the host and the resource's path.

The same shape as RFC 8414 and for the same reason: a resource identified by
``https://gw.example/mcp`` publishes at
``https://gw.example/.well-known/oauth-protected-resource/mcp``, so one host can
serve several protected resources without their metadata documents colliding.
Appending, the way OpenID Connect Discovery does, would put the document
*inside* the resource's own path space and make it indistinguishable from the
resource's own routes.
"""

DEFAULT_RESOURCE_NAME = "agent-control-plane"

BEARER_METHODS = ("header",)
"""How this gateway will accept a token, and only how.

Not a formality. RFC 6750 also defines a ``access_token`` query parameter and a
form-encoded body parameter, and both are ways to get a bearer credential
written into an access log, a proxy's request line, a browser's ``Referer``
header and every metrics pipeline in between. ``acp.identity.asgi`` reads the
``Authorization`` header and nothing else; this is that fact, published. A test
asserts the two agree, because a capability document that describes a different
program than the one serving it is worse than no document.
"""


@dataclass(frozen=True, slots=True)
class ProtectedResource:
    """This gateway, described the way RFC 9728 describes a resource server."""

    resource: str
    """The resource identifier. An absolute URI, and the audience a token for
    this gateway must carry."""

    authorization_servers: tuple[str, ...] = ()
    """Issuer identifiers a client may authenticate against, in the form RFC
    8414 discovery expects — which is exactly ``IssuerRegistry.issuers``."""

    resource_name: str = DEFAULT_RESOURCE_NAME
    scopes_supported: tuple[str, ...] = ()
    resource_documentation: str = ""

    def __post_init__(self) -> None:
        _reject_unusable_resource(self.resource)

    @property
    def metadata_path(self) -> str:
        """The path this document is served at, and the only unauthenticated
        path in the gateway. Derived from the resource identifier rather than
        configured, so the two cannot drift apart."""
        path = urlsplit(self.resource).path.rstrip("/")
        return f"/{WELL_KNOWN_SEGMENT}{path}"

    @property
    def metadata_url(self) -> str:
        """The absolute URL that goes in the ``WWW-Authenticate`` challenge.

        Absolute rather than a path, because RFC 9728 §5.1 says so and because a
        client behind a proxy cannot reliably reconstruct the origin it reached
        this gateway on. Built from the resource identifier, which is the one
        piece of configuration that *does* know the public origin.
        """
        parts = urlsplit(self.resource)
        return urlunsplit((parts.scheme, parts.netloc, self.metadata_path, "", ""))

    def document(self) -> dict[str, Any]:
        """The JSON body, with absent things absent.

        Optional members are omitted rather than emitted empty. ``"scopes_
        supported": []`` is a claim — that this resource has no scopes — and
        saying nothing is a different and, until Phase 3 defines them, more
        accurate statement.
        """
        document: dict[str, Any] = {"resource": self.resource}
        if self.authorization_servers:
            document["authorization_servers"] = list(self.authorization_servers)
        document["bearer_methods_supported"] = list(BEARER_METHODS)
        if self.resource_name:
            document["resource_name"] = self.resource_name
        if self.scopes_supported:
            document["scopes_supported"] = list(self.scopes_supported)
        if self.resource_documentation:
            document["resource_documentation"] = self.resource_documentation
        return document


def protected_resource(
    resource: str,
    *,
    authorization_servers: Iterable[str] = (),
    resource_name: str = DEFAULT_RESOURCE_NAME,
    scopes_supported: Iterable[str] = (),
    resource_documentation: str = "",
) -> ProtectedResource:
    """Build one from iterables, so callers need not remember to make tuples."""
    return ProtectedResource(
        resource=resource,
        authorization_servers=tuple(authorization_servers),
        resource_name=resource_name,
        scopes_supported=tuple(scopes_supported),
        resource_documentation=resource_documentation,
    )


def metadata_route(resource: ProtectedResource) -> Route:
    """The route serving the document.

    Rendered once, at construction. The document is derived entirely from
    startup configuration and cannot change while the process runs, so building
    it per request would be work done to produce a constant — and it would make
    an unauthenticated endpoint's cost proportional to how often it is called,
    which is a property worth not having on the one route anybody can reach.

    ``Cache-Control`` for the same reason from the other end: without it a
    client re-fetches this after every 401, and 401s are the normal state of a
    client whose token has just expired.
    """
    document = resource.document()

    async def serve(_request: Request) -> Response:
        return JSONResponse(document, headers={"Cache-Control": "public, max-age=3600"})

    return Route(
        resource.metadata_path,
        serve,
        methods=["GET"],
        name="oauth-protected-resource",
    )


def _reject_unusable_resource(resource: str) -> None:
    """Startup validation, with the same discipline as ``discovery``.

    Every failure here is fatal. A resource identifier that a client cannot use
    produces a discovery chain that ends in a token this gateway rejects, and
    that failure surfaces as "authentication is broken" three systems away from
    the typo that caused it.
    """
    parts = urlsplit(resource)
    if not parts.scheme or not parts.netloc:
        msg = (
            f"resource identifier {resource!r} is not an absolute URI. It is the "
            f"audience a client asks the authorization server for (RFC 8707 §2), "
            f"and a relative reference cannot identify this gateway to a third party."
        )
        raise ConfigurationError(msg)
    if parts.fragment:
        # RFC 8707 §2: the resource indicator MUST NOT include a fragment. A
        # fragment never leaves the client anyway, so an identifier that relies
        # on one is two different strings on the two sides of the exchange.
        msg = f"resource identifier {resource!r} must not contain a fragment (RFC 8707 §2)"
        raise ConfigurationError(msg)
    if parts.query:
        # Permitted by RFC 8707 and refused here: RFC 9728 §3.1 builds the
        # metadata URL by inserting a path segment, and there is no defined
        # place to put a query string in that construction. Allowing it would
        # mean publishing at a URL a client cannot derive.
        msg = (
            f"resource identifier {resource!r} must not contain a query string. "
            f"RFC 9728 §3.1 derives the metadata URL by inserting a path segment, "
            f"and a query has nowhere to go in that construction."
        )
        raise ConfigurationError(msg)
    if parts.scheme != "https" and parts.hostname not in LOOPBACK_HOSTS:
        msg = (
            f"resource identifier {resource!r} must use https. This value is "
            f"published to unauthenticated callers and used to derive the URL they "
            f"fetch next; over plain HTTP both can be rewritten in transit, which "
            f"points a client at an authorization server of the attacker's choosing."
        )
        raise ConfigurationError(msg)
