"""RFC 9728 protected resource metadata: tells a client which authorization server to use.

A 401 points at this document, which names the servers; the client then runs RFC 8414
discovery. It is public by necessity, exempting exactly ``metadata_path``, and names the
trusted servers by design (contrast ADR 0010). Its ``resource`` is the audience a token
must carry, so ``runtime`` warns when no issuer is expected to mint it.
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
"""RFC 9728 §3.1: inserted between host and path, so resources on one host do not collide."""

DEFAULT_RESOURCE_NAME = "agent-control-plane"

BEARER_METHODS = ("header",)
"""Token transports accepted: header only, matching ``acp.identity.asgi`` (a test asserts it).

Query and body tokens leak into logs and ``Referer`` headers.
"""


@dataclass(frozen=True, slots=True)
class ProtectedResource:
    """This gateway, described the way RFC 9728 describes a resource server."""

    resource: str
    """Absolute URI identifying this gateway; also the audience a token must carry."""

    authorization_servers: tuple[str, ...] = ()
    """Issuer identifiers for RFC 8414 discovery, i.e. ``IssuerRegistry.issuers``."""

    resource_name: str = DEFAULT_RESOURCE_NAME
    scopes_supported: tuple[str, ...] = ()
    resource_documentation: str = ""

    def __post_init__(self) -> None:
        _reject_unusable_resource(self.resource)

    @property
    def metadata_path(self) -> str:
        """Return the path this document is served at: the only unauthenticated path."""
        path = urlsplit(self.resource).path.rstrip("/")
        return f"/{WELL_KNOWN_SEGMENT}{path}"

    @property
    def metadata_url(self) -> str:
        """Return the absolute URL for the ``WWW-Authenticate`` challenge (RFC 9728 §5.1)."""
        parts = urlsplit(self.resource)
        return urlunsplit((parts.scheme, parts.netloc, self.metadata_path, "", ""))

    def document(self) -> dict[str, Any]:
        """Return the JSON body, omitting empty optional members."""
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
    """Build a ``ProtectedResource`` from iterables."""
    return ProtectedResource(
        resource=resource,
        authorization_servers=tuple(authorization_servers),
        resource_name=resource_name,
        scopes_supported=tuple(scopes_supported),
        resource_documentation=resource_documentation,
    )


def metadata_route(resource: ProtectedResource) -> Route:
    """Return the GET route serving the document.

    Rendered once at construction and served with ``Cache-Control``, so this public route
    costs nothing per call.
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
    """Validate the resource identifier at startup; every failure is fatal."""
    parts = urlsplit(resource)
    if not parts.scheme or not parts.netloc:
        msg = (
            f"resource identifier {resource!r} is not an absolute URI. It is the "
            f"audience a client asks the authorization server for (RFC 8707 §2), "
            f"and a relative reference cannot identify this gateway to a third party."
        )
        raise ConfigurationError(msg)
    if parts.fragment:
        # RFC 8707 §2 forbids a fragment.
        msg = f"resource identifier {resource!r} must not contain a fragment (RFC 8707 §2)"
        raise ConfigurationError(msg)
    if parts.query:
        # Allowed by RFC 8707, but RFC 9728 §3.1 has nowhere to put a query.
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
