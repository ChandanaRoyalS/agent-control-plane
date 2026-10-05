"""Authorization server metadata discovery, verifying the server answered for itself.

RFC 8414 §3.3: the metadata ``issuer`` must be identical to the configured issuer, so a
key set cannot be attributed to the wrong server. Both URL forms are tried (RFC 8414
inserts the well-known segment, OIDC Discovery appends it). Comparison is exact, with no
slash or case normalisation; the error names the trailing-slash case.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from acp.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

OAUTH_SEGMENT = ".well-known/oauth-authorization-server"
"""RFC 8414 §3.1 — inserted between the host and the issuer's path."""

OIDC_SEGMENT = ".well-known/openid-configuration"
"""OpenID Connect Discovery 1.0 §4 — appended to the issuer."""

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
"""Hosts that may serve metadata over plain HTTP; others need https (RFC 8414 §2).

Container hosts such as ``keycloak`` are not loopback and must be named in ``insecure_hosts``.
"""

DEFAULT_TIMEOUT = 5.0


def plaintext_permitted(hostname: str | None, insecure_hosts: Iterable[str] = ()) -> bool:
    """Return whether this host may serve its metadata over plain HTTP.

    ``insecure_hosts`` is an explicit operator list, empty by default; startup warns for
    every entry. See ADR 0018.
    """
    if hostname is None:
        return False
    return hostname in LOOPBACK_HOSTS or hostname in set(insecure_hosts)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The parts of an authorization server's metadata this gateway uses."""

    issuer: str
    jwks_uri: str
    source: str
    token_endpoint: str = ""
    """Token endpoint for RFC 8693 exchange; empty if the server publishes none.

    Taken from verified metadata (RFC 8414 §3.3), never configured. Missing is fatal only
    in ``build_token_exchanger``.
    """
    """Which URL answered (logged)."""


async def discover(
    issuer: str,
    *,
    client: httpx.AsyncClient | None = None,
    # Not `timeout`, which trips ruff ASYNC109; this is an httpx client timeout.
    request_timeout: float = DEFAULT_TIMEOUT,
    insecure_hosts: Iterable[str] = (),
) -> ProviderMetadata:
    """Fetch and validate an authorization server's metadata.

    Raises:
        ConfigurationError: On any failure; this runs at startup and must stop it.
    """
    _reject_unusable_issuer(issuer, insecure_hosts)

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=request_timeout, follow_redirects=False)
    try:
        failures: list[str] = []
        for url in candidate_urls(issuer):
            document = await _fetch(http, url, failures)
            if document is None:
                continue
            metadata = _validate(document, issuer, url)
            logger.info(
                "auth.discovered",
                extra={"issuer": issuer, "jwks_uri": metadata.jwks_uri, "source": url},
            )
            return metadata
    finally:
        if owns_client:
            await http.aclose()

    msg = (
        f"could not discover metadata for issuer {issuer!r}. Tried: "
        + "; ".join(failures)
        + ". Set the JWKS URL explicitly if this server does not publish metadata."
    )
    raise ConfigurationError(msg)


def candidate_urls(issuer: str) -> list[str]:
    """Return both well-known URLs, RFC 8414's first and the OIDC form as fallback."""
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")

    inserted = urlunsplit((parts.scheme, parts.netloc, f"/{OAUTH_SEGMENT}{path}", "", ""))
    appended = urlunsplit((parts.scheme, parts.netloc, f"{path}/{OIDC_SEGMENT}", "", ""))
    return [inserted, appended]


def _reject_unusable_issuer(issuer: str, insecure_hosts: Iterable[str] = ()) -> None:
    parts = urlsplit(issuer)
    if parts.query or parts.fragment:
        # RFC 8414 §2: a query breaks identifier equality.
        msg = f"issuer {issuer!r} must not contain a query string or fragment (RFC 8414 §2)"
        raise ConfigurationError(msg)
    if not parts.netloc:
        msg = f"issuer {issuer!r} is not an absolute URL"
        raise ConfigurationError(msg)
    if parts.scheme != "https" and not plaintext_permitted(parts.hostname, insecure_hosts):
        msg = (
            f"issuer {issuer!r} must use https (RFC 8414 §2). Metadata fetched over "
            f"plain HTTP can be rewritten in transit, and this document decides "
            f"which signing keys the gateway trusts. If this is a development "
            f"identity provider on a private network, name its host in "
            f"ACP_AUTH_INSECURE_ISSUER_HOSTS — deliberately, and knowing that every "
            f"start logs a warning naming it."
        )
        raise ConfigurationError(msg)


async def _fetch(
    client: httpx.AsyncClient, url: str, failures: list[str]
) -> dict[str, object] | None:
    """Fetch one candidate URL; ``None`` means try the next.

    Redirects are not followed, since a redirected document is not served where the
    issuer says.
    """
    try:
        response = await client.get(url)
    except httpx.HTTPError as exc:
        failures.append(f"{url} ({type(exc).__name__})")
        return None

    if response.status_code != httpx.codes.OK:
        failures.append(f"{url} (HTTP {response.status_code})")
        return None

    try:
        document = response.json()
    except ValueError:
        failures.append(f"{url} (not JSON)")
        return None

    if not isinstance(document, dict):
        failures.append(f"{url} (not a JSON object)")
        return None
    return document


def _validate(document: dict[str, object], issuer: str, url: str) -> ProviderMetadata:
    """Check RFC 8414 §3.3 and extract the fields used.

    An issuer mismatch is fatal, not a reason to try the next URL.
    """
    declared = document.get("issuer")
    if declared != issuer:
        raise ConfigurationError(_mismatch_message(declared, issuer, url))

    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        msg = f"metadata at {url} declares no `jwks_uri`, so there are no keys to verify with"
        raise ConfigurationError(msg)

    token_endpoint = document.get("token_endpoint")
    return ProviderMetadata(
        issuer=issuer,
        jwks_uri=jwks_uri,
        source=url,
        token_endpoint=token_endpoint if isinstance(token_endpoint, str) else "",
    )


def _mismatch_message(declared: object, issuer: str, url: str) -> str:
    base = (
        f"metadata at {url} declares issuer {declared!r}, but this gateway was "
        f"configured to trust {issuer!r}. RFC 8414 §3.3 requires them to be identical; "
        f"they are not, so the key set published there cannot be attributed to the "
        f"issuer being trusted."
    )
    if isinstance(declared, str) and declared.rstrip("/") == issuer.rstrip("/"):
        # Commonest case, and invisible in a terminal.
        return (
            base + " These differ only by a trailing slash: use the exact string "
            "the server publishes."
        )
    return base
