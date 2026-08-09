"""Asking an authorization server where its keys are, and checking it answered for itself.

Configuring a JWKS URL by hand works and quietly permits the exact confusion
this phase is about: nothing anywhere checks that the key set you pointed at
belongs to the issuer you said you trust. Paste the wrong line into the wrong
environment file and the gateway will happily verify tokens from one
authorization server while believing they came from another — a mix-up achieved
without an attacker, by a copy-paste.

Discovery closes that, and the closing move is one sentence of RFC 8414 §3.3:
the ``issuer`` in the metadata document **must be identical** to the issuer
identifier the URL was built from. The document is fetched from a location
derived from the issuer, and it has to name that same issuer back. A server
cannot claim to be somebody else without also being hosted where that somebody
else's metadata lives.

**Two URL shapes, because there are two specifications.** RFC 8414 *inserts*
the well-known segment between the host and the path, so
``https://host/realms/acp`` becomes
``https://host/.well-known/oauth-authorization-server/realms/acp``. OpenID
Connect Discovery *appends* it, giving
``https://host/realms/acp/.well-known/openid-configuration``. Real deployments
serve one, the other, or both — Keycloak serves both — and a client that knows
only one form fails against half the world for a reason that looks like a
network problem.

**Identical means identical.** No trailing-slash normalisation, no case folding.
Normalising would mean this gateway's notion of "the same authorization server"
differs from the specification's, which is precisely the disagreement the check
exists to detect. It does cost a confusing failure for the commonest typo, so
the error message calls that case out by name.
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
"""Hosts allowed to serve metadata over plain HTTP without anyone asking.

RFC 8414 §2 requires the issuer to use ``https``, and it is right to: metadata
fetched over HTTP can be rewritten in flight, and this document is what decides
which keys the gateway will trust. Loopback is exempt because traffic that never
leaves the machine has no in-flight to be rewritten in.

Note what this does *not* cover: one container talking to another. When Keycloak
arrived in Compose (task 26) the issuer became ``http://keycloak:8080`` — not
loopback, not TLS, and refused by this rule. That is the rule working correctly,
and the answer is ``insecure_hosts`` below rather than a wider default.
"""

DEFAULT_TIMEOUT = 5.0


def plaintext_permitted(hostname: str | None, insecure_hosts: Iterable[str] = ()) -> bool:
    """Whether this host may serve its metadata over plain HTTP.

    ``insecure_hosts`` is an operator-named list, empty by default, and it is the
    escape hatch built on purpose so that nobody builds a worse one by accident.
    The alternatives actually on the table when Keycloak arrived were adding
    ``keycloak`` to ``LOOPBACK_HOSTS`` — a lie, and one that would ship to every
    deployment — or turning certificate verification off, which is broader than
    this, quieter than this, and invisible in a config file. See ADR 0018.

    Naming a host here is a decision rather than a default: it appears in
    configuration as a hostname somebody typed, and startup logs a warning for
    every entry.
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
    """Which URL answered. Logged, because "discovery worked" and "discovery
    worked *via the OIDC form*" are different facts when debugging a server that
    only implements one of them."""


async def discover(
    issuer: str,
    *,
    client: httpx.AsyncClient | None = None,
    # Named `request_timeout` rather than `timeout`: ruff's ASYNC109 flags a
    # `timeout` parameter on an async function, on the reasonable grounds that
    # it usually means somebody is reimplementing cancellation by hand. Here it
    # is an httpx connection timeout being passed to a client, which is the
    # thing ASYNC109 tells you to use instead.
    request_timeout: float = DEFAULT_TIMEOUT,
    insecure_hosts: Iterable[str] = (),
) -> ProviderMetadata:
    """Fetch and validate an authorization server's metadata.

    Raises ``ConfigurationError`` for everything, because this runs at startup
    and every failure here is a deployment that must not begin serving. A
    gateway that starts with an unverified idea of which keys to trust has
    already lost the property this module exists to provide.
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
    """Both well-known forms, RFC 8414's first.

    RFC 8414's is tried first because it is the OAuth specification and this is
    an OAuth resource server; the OpenID form is the fallback for the many
    servers that only implement OIDC Discovery.
    """
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")

    inserted = urlunsplit((parts.scheme, parts.netloc, f"/{OAUTH_SEGMENT}{path}", "", ""))
    appended = urlunsplit((parts.scheme, parts.netloc, f"{path}/{OIDC_SEGMENT}", "", ""))
    return [inserted, appended]


def _reject_unusable_issuer(issuer: str, insecure_hosts: Iterable[str] = ()) -> None:
    parts = urlsplit(issuer)
    if parts.query or parts.fragment:
        # RFC 8414 §2. A query string in an identifier means two spellings of
        # the same server compare unequal, and equality is the whole mechanism.
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
    """One candidate URL. ``None`` means try the next one.

    Redirects are not followed. A metadata document reached by redirect is a
    document served from somewhere other than where the issuer's identity says
    it should be, which is the property being checked — so following one would
    quietly undo the check.
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
    """RFC 8414 §3.3, and the one field this gateway needs.

    A mismatch here is fatal rather than a reason to try the next candidate URL.
    A server that answered *and named somebody else* is not a server that failed
    to answer — it is the exact condition this function exists to detect, and
    moving on to the next URL would be looking for a server willing to agree
    with us.
    """
    declared = document.get("issuer")
    if declared != issuer:
        raise ConfigurationError(_mismatch_message(declared, issuer, url))

    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        msg = f"metadata at {url} declares no `jwks_uri`, so there are no keys to verify with"
        raise ConfigurationError(msg)

    return ProviderMetadata(issuer=issuer, jwks_uri=jwks_uri, source=url)


def _mismatch_message(declared: object, issuer: str, url: str) -> str:
    base = (
        f"metadata at {url} declares issuer {declared!r}, but this gateway was "
        f"configured to trust {issuer!r}. RFC 8414 §3.3 requires them to be identical; "
        f"they are not, so the key set published there cannot be attributed to the "
        f"issuer being trusted."
    )
    if isinstance(declared, str) and declared.rstrip("/") == issuer.rstrip("/"):
        # By far the commonest way to hit this, and the least informative if
        # left unexplained — the two strings look the same in a terminal.
        return (
            base + " These differ only by a trailing slash: use the exact string "
            "the server publishes."
        )
    return base
