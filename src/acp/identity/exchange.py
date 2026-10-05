"""RFC 8693 token exchange: a short-lived credential scoped to one upstream, per call.

The exchange goes to the token endpoint of the issuer that minted the subject token
(ADR 0016). This is the only reader of the inbound token, and a failed exchange fails the
call; nothing is forwarded or sent uncredentialed. The returned credential is checked
against the request, because Keycloak ignores RFC 8707 ``resource``
(`scripts/probe_resource_indicator.py`, ADR 0020).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from acp.audit import AuditLog
from acp.audit import Category as AuditCategory
from acp.audit import Outcome as AuditOutcome
from acp.exceptions import (
    ConfigurationError,
    CredentialExchangeError,
    CredentialProviderUnavailableError,
)
from acp.identity.cache import CredentialCache, CredentialKey
from acp.identity.discovery import plaintext_permitted
from acp.identity.issuers import IssuerRegistry
from acp.identity.principal import current_principal, current_subject_token
from acp.observability import metrics

logger = logging.getLogger(__name__)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 — type URN

DEFAULT_TIMEOUT = 10.0
"""Token endpoint timeout in seconds; on the request path, so part of caller latency."""

DEFAULT_EXPIRY_SKEW = 30.0
"""Seconds early a token counts as expired, so it cannot expire in flight upstream.

The cache refreshes against this margin; an uncached exchange only records it.
"""


@dataclass(frozen=True, slots=True)
class ExchangedToken:
    """A credential for exactly one upstream."""

    access_token: str
    audience: str
    issuer: str
    expires_at: float | None

    def expired(self, *, now: float | None = None, skew: float = DEFAULT_EXPIRY_SKEW) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at - skew

    def __repr__(self) -> str:
        """Return a repr that never includes the token."""
        return f"ExchangedToken(audience={self.audience!r}, expires_at={self.expires_at!r})"


class TokenExchanger:
    """Exchanges an inbound token for an upstream-scoped one."""

    def __init__(
        self,
        issuers: IssuerRegistry,
        *,
        client_id: str,
        client_secret: str,
        peer_audiences: Iterable[str] = (),
        cache: CredentialCache | None = None,
        audit: AuditLog | None = None,
        http: httpx.AsyncClient | None = None,
        request_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.issuers = issuers
        self._client_id = client_id
        self._client_secret = client_secret
        self._audit = audit
        # Audiences this gateway brokers for, used only to reject a credential that opens
        # another upstream. Empty is valid for a single-upstream deployment.
        self._peers = frozenset(peer_audiences)
        # `None` disables caching (useful in tests); see `runtime.build_token_exchanger`.
        self._cache = cache
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(timeout=request_timeout)

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def exchange(
        self, *, subject_token: str, issuer: str, audience: str, resource: str = ""
    ) -> ExchangedToken:
        """Return a credential for this upstream, from cache or freshly minted.

        Single-flight: the cache is re-checked under the per-key lock so queued callers do
        not each mint.
        """
        if self._cache is None:
            return await self._mint(
                subject_token=subject_token, issuer=issuer, audience=audience, resource=resource
            )

        key = CredentialKey.of(subject_token, audience, resource)
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.record(hit=True)
            metrics.record_credential_cache(outcome="hit")
            return cached

        async with self._cache.lock_for(key):
            # Whoever was minting while this call waited has already stored it.
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.record(hit=True)
                metrics.record_credential_cache(outcome="hit")
                return cached

            self._cache.record(hit=False)
            metrics.record_credential_cache(outcome="miss")
            token = await self._mint(
                subject_token=subject_token, issuer=issuer, audience=audience, resource=resource
            )
            self._cache.put(key, token)
            return token

    async def _mint(
        self, *, subject_token: str, issuer: str, audience: str, resource: str
    ) -> ExchangedToken:
        """One exchange, against the issuer that minted the subject token."""
        registration = self.issuers.registration_for(issuer)
        endpoint = registration.token_endpoint
        if not endpoint:
            # Never guess an endpoint from the issuer URL.
            msg = f"issuer {issuer!r} has no token endpoint, so no credential can be minted"
            raise CredentialExchangeError(msg)

        form = {
            "grant_type": GRANT_TYPE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": audience,
        }
        if resource:
            # RFC 8707; sent but not relied on, see `_verify_scope`.
            form["resource"] = resource
        try:
            response = await self._http.post(
                endpoint,
                data=form,
                auth=(self._client_id, self._client_secret),
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            # Unreachable server: retryable and not the caller's fault (503, not 401).
            logger.warning(
                "auth.exchange_unreachable",
                extra={"issuer": issuer, "audience": audience, "error": type(exc).__name__},
            )
            msg = f"could not reach the token endpoint for {issuer!r}"
            raise CredentialProviderUnavailableError(msg) from exc

        token = await self._token_from(response, issuer=issuer, audience=audience)
        self._verify_scope(token)
        return token

    async def _token_from(
        self, response: httpx.Response, *, issuer: str, audience: str
    ) -> ExchangedToken:
        if response.status_code != httpx.codes.OK:
            raise self._refused(response, issuer=issuer, audience=audience)

        try:
            payload = response.json()
        except ValueError as exc:
            msg = f"the token endpoint for {issuer!r} did not return JSON"
            raise CredentialProviderUnavailableError(msg) from exc

        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            msg = f"the token endpoint for {issuer!r} returned no access_token"
            raise CredentialExchangeError(msg)

        expires_in = payload.get("expires_in")
        numeric = isinstance(expires_in, int | float)
        expires_at = time.time() + float(expires_in) if numeric else None

        logger.info(
            "auth.exchanged",
            extra={
                "issuer": issuer,
                "audience": audience,
                # Never the token.
                "expires_in": expires_in,
            },
        )
        acting = current_principal()
        if self._audit is not None:
            # Never the token: audience and lifetime are the record. The principal comes
            # from the contextvar the authentication middleware bound.
            await self._audit.arecord(
                AuditCategory.CREDENTIAL,
                "auth.exchanged",
                subject=acting.subject if acting else None,
                actor=acting.actor.subject if acting and acting.actor else None,
                tenant=acting.tenant if acting else None,
                upstream=audience,
                outcome=AuditOutcome.ALLOWED,
                detail={"issuer": issuer, "expires_in": expires_in},
            )
        return ExchangedToken(
            access_token=token, audience=audience, issuer=issuer, expires_at=expires_at
        )

    def _verify_scope(self, token: ExchangedToken) -> None:
        """Check the returned credential against the one requested.

        The real scope control, since RFC 8707 only recommends ``invalid_target``. The
        credential must name the target and must not name another brokered upstream
        (confused deputy). Audiences that are not upstreams are ignored.

        Raises:
            CredentialExchangeError: Wrong target, or valid at another upstream.
        """
        audiences = _audiences_of(token.access_token)
        if audiences is None:
            # Opaque token: cannot be checked, so warn rather than refuse (SECURITY.md).
            logger.warning(
                "auth.scope_unverifiable",
                extra={
                    "audience": token.audience,
                    "reason": "the exchanged credential is not a JWT",
                    "consequence": "the gateway cannot confirm it is scoped to one upstream",
                },
            )
            return

        if token.audience not in audiences:
            logger.warning(
                "auth.scope_wrong_target",
                extra={"requested": token.audience, "received": sorted(audiences)},
            )
            msg = (
                f"the authorization server returned a credential that is not for {token.audience!r}"
            )
            raise CredentialExchangeError(msg)

        crossed = (audiences & self._peers) - {token.audience}
        if crossed:
            logger.error(
                "auth.scope_too_broad",
                extra={
                    "requested": token.audience,
                    "also_valid_for": sorted(crossed),
                    "consequence": "this credential would let one upstream act at another",
                },
            )
            msg = (
                f"the authorization server returned a credential for {token.audience!r} "
                f"that is also valid at {len(crossed)} other upstream(s); it was asked "
                f"for one and would open several"
            )
            raise CredentialExchangeError(msg)

    def _refused(
        self, response: httpx.Response, *, issuer: str, audience: str
    ) -> CredentialExchangeError:
        """Turn a token endpoint refusal into an error; 5xx means unavailable.

        The RFC 6749 §5.2 body is logged, never returned to the caller.
        """
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                detail = f"{body.get('error')}: {body.get('error_description')}"
        except ValueError:
            detail = response.text[:200]

        server_error = response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR
        logger.warning(
            "auth.exchange_refused",
            extra={
                "issuer": issuer,
                "audience": audience,
                "status": response.status_code,
                "detail": detail,
            },
        )
        msg = f"the authorization server refused to issue a credential for {audience!r}"
        if server_error:
            return CredentialProviderUnavailableError(msg)
        return CredentialExchangeError(msg)


class ExchangedCredentials:
    """Supplies the ``Authorization`` header for one outbound request.

    The upstream client never touches an inbound token; it has one of these or ``None``.
    """

    def __init__(self, exchanger: TokenExchanger) -> None:
        self._exchanger = exchanger

    async def authorization_for(
        self, upstream: str, audience: str, resource: str = ""
    ) -> str | None:
        """Return a ``Bearer`` value for this upstream, or ``None`` when there is no caller.

        ``None`` only for the background health prober, which has no principal and so
        reaches upstreams uncredentialed (a known gap). With exchange configured,
        ``ACP_AUTH_REQUIRED`` ensures every request-path call has a principal.
        """
        principal = current_principal()
        subject_token = current_subject_token()
        if principal is None or subject_token is None:
            logger.debug(
                "auth.exchange_skipped",
                extra={"upstream": upstream, "reason": "no principal on this call"},
            )
            return None

        token = await self._exchanger.exchange(
            subject_token=subject_token,
            issuer=principal.issuer,
            audience=audience,
            resource=resource,
        )
        return f"Bearer {token.access_token}"


def _audiences_of(token: str) -> frozenset[str] | None:
    """Return a JWT's `aud`, or ``None`` when it is not a readable JWT.

    Not signature-verified: this is a scope check on a token just received over TLS from
    an authenticated endpoint. ``None`` (unreadable) is distinct from an empty set.
    """
    parts = token.split(".")
    expected_segments = 3
    if len(parts) != expected_segments:
        return None
    try:
        segment = parts[1]
        payload = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        claims = json.loads(payload)
    except (ValueError, binascii.Error):
        return None
    if not isinstance(claims, dict):
        return None

    audience = claims.get("aud")
    if isinstance(audience, str):
        return frozenset({audience})
    if isinstance(audience, list):
        return frozenset(a for a in audience if isinstance(a, str))
    return frozenset()


def require_token_endpoints(issuers: IssuerRegistry, insecure_hosts: Iterable[str] = ()) -> None:
    """Refuse to start when exchange is configured and an issuer cannot do it.

    Raises:
        ConfigurationError: An issuer has no token endpoint, or a plaintext one; the
            exchange POSTs the client secret and caller's token. Hosts in
            `ACP_AUTH_INSECURE_ISSUER_HOSTS` are exempt.
    """
    missing = [r.issuer for r in issuers if not r.token_endpoint]
    if missing:
        msg = (
            f"token exchange is configured, but no token endpoint is known for: "
            f"{', '.join(sorted(missing))}. It is normally discovered from the issuer's "
            f"metadata — an explicit ACP_AUTH_JWKS_URL skips that discovery, in which "
            f"case set ACP_AUTH_TOKEN_ENDPOINT as well."
        )
        raise ConfigurationError(msg)
    for registration in issuers:
        parts = urlsplit(registration.token_endpoint)
        if parts.scheme == "https" or plaintext_permitted(parts.hostname, insecure_hosts):
            continue
        msg = (
            f"issuer {registration.issuer!r}: token endpoint {registration.token_endpoint!r} "
            f"must use https. The exchange sends the client secret and the caller's token "
            f"to it, and over plain HTTP anything on the path reads both."
        )
        raise ConfigurationError(msg)
