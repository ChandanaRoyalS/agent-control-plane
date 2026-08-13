"""Minting a short-lived credential for one upstream — RFC 8693.

This is the task the whole phase was built toward, and the problem it closes is
worth restating in one sentence: an agent wired into internal systems normally
holds one credential per system carrying the union of every permission any user
might need, so the same request reaches the same data whether it was made for an
intern or for the CFO.

Everything before this established *who* is asking. This changes *what the
upstream is handed*. For each call the gateway presents the caller's token to
the authorization server and asks for a different one — same subject, narrower
audience, minutes of lifetime, scoped to exactly one upstream. The gateway holds
no long-lived upstream credential at all, because there is nothing for it to
hold: the credential is made per call and expires before anyone could reuse it.

**The exchange goes back to the server that issued the token.** Not to a
configured token endpoint, not to a default one: the subject token's ``iss``
selects the registration, and the request goes to *that* registration's endpoint
(ADR 0016). Sending one authorization server's token to another's token endpoint
is the mix-up attack wearing a helpful face — the second server cannot validate
it, and if it could, it would be minting credentials on the first one's say-so.

**The inbound token goes here and nowhere else.** It is read from
``current_subject_token()``, whose whole reason for existing separately from the
``Principal`` is that exactly one module should be able to reach it. The
invariant task 31 has to prove is a statement about this file.

**A failed exchange fails the call.** The two alternatives are to call the
upstream with no credential, which is a gateway that has silently stopped
enforcing the thing it exists for, or to forward the caller's own token, which
is the passthrough this phase exists to make impossible. Neither is a
degradation worth having; refusing is.

**Asking for a scope is not the same as getting one** (task 28). RFC 8707 §2
says an authorization server that cannot honour a `resource` request SHOULD
answer `invalid_target`. Keycloak 26.7, measured rather than assumed, accepts
the parameter and discards it — including when it directly contradicts
`audience`, where it returns a token for the *audience* and no error at all
(`scripts/probe_resource_indicator.py`, ADR 0020).

So the credential that comes back is checked against the one that was asked
for. It must name the requested target, and it must not name any *other*
upstream this gateway brokers for. That second half is the confused-deputy
condition stated exactly: a credential that opens two doors is not a credential
scoped to one, however it was requested.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass

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
from acp.identity.issuers import IssuerRegistry
from acp.identity.principal import current_principal, current_subject_token
from acp.observability import metrics

logger = logging.getLogger(__name__)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 — a
# token *type* identifier from RFC 8693 §3, not a token. Suppressed rather than
# renamed: the rule is right to be suspicious of a constant ending in "token".

DEFAULT_TIMEOUT = 10.0
"""Longer than discovery's five seconds, and shorter than any upstream's read
timeout. This runs on the request path, so it is part of the caller's latency
budget — but it is a token endpoint doing signing work, not a metadata document
being served from memory."""

DEFAULT_EXPIRY_SKEW = 30.0
"""Treated as expired this many seconds early.

A token that is valid when the gateway checks it and expired when the upstream
does is the worst possible outcome, because it fails *after* the side effect
might have happened. Task 30 refreshes against this margin; task 27 only records
it, since nothing is cached yet.
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
        """Never the token.

        A credential that reaches a log or a traceback has escaped, and the
        commonest way that happens is a dataclass repr in an exception message
        nobody meant to print. The default here would have done exactly that.
        """
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
        # Every audience this gateway brokers for. Used only to answer one
        # question about a credential that has just been minted: does it also
        # open somebody else's door? Empty is not a failure — it just means the
        # cross-upstream check has nothing to compare against, which is the
        # correct state for a single-upstream deployment.
        self._peers = frozenset(peer_audiences)
        # `None` disables caching entirely, which is task 27's behaviour and the
        # right shape for a test that wants to count exchanges. Every deployment
        # has one; see `runtime.build_token_exchanger`.
        self._cache = cache
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(timeout=request_timeout)

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def exchange(
        self, *, subject_token: str, issuer: str, audience: str, resource: str = ""
    ) -> ExchangedToken:
        """A credential for this upstream — cached, or minted and then cached.

        The cache is checked, then a per-key lock is taken, then the cache is
        checked *again*. That second read is the whole single-flight mechanism
        and it is easy to leave out: without it, every request that queued on the
        lock while the first one was minting proceeds to mint its own. Task 22
        shipped exactly that defect in the JWKS cache, where twenty concurrent
        misses produced twenty-one fetches — found by asserting a *count* rather
        than a type.
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
            # Startup should have caught this. If it did not, refusing beats
            # improvising an endpoint from the issuer URL — a guessed token
            # endpoint is a credential sent somewhere nobody chose.
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
            # RFC 8707. Sent because it is the specified way to name a target
            # and any conformant server acts on it; not *relied* on, because the
            # one server this project runs against does not. See `_verify_scope`.
            form["resource"] = resource
        try:
            response = await self._http.post(
                endpoint,
                data=form,
                auth=(self._client_id, self._client_secret),
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            # The authorization server is unreachable or misbehaving. Worth
            # retrying, and emphatically not the caller's fault — the same
            # distinction task 22 drew between 401 and 503.
            logger.warning(
                "auth.exchange_unreachable",
                extra={"issuer": issuer, "audience": audience, "error": type(exc).__name__},
            )
            msg = f"could not reach the token endpoint for {issuer!r}"
            raise CredentialProviderUnavailableError(msg) from exc

        token = self._token_from(response, issuer=issuer, audience=audience)
        self._verify_scope(token)
        return token

    def _token_from(
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
                # Never the token. The lifetime is the interesting number and
                # the only one safe to write down.
                "expires_in": expires_in,
            },
        )
        acting = current_principal()
        if self._audit is not None:
            # The credential half of the plan's four categories. Never the token:
            # the audience and the lifetime are what an auditor needs — *which
            # door was opened, for how long* — and the token itself is the one
            # value whose presence in a durable file would be a breach rather
            # than a record.
            #
            # The principal comes from the contextvar rather than being
            # threaded down, because that is where it already is: the
            # exchange happens inside the request whose principal the
            # authentication middleware bound. Passing it through four
            # signatures to arrive at the same value would be four more
            # places for it to be dropped.
            self._audit.record(
                AuditCategory.CREDENTIAL,
                "auth.exchanged",
                subject=acting.subject if acting else None,
                actor=acting.actor.subject if acting and acting.actor else None,
                upstream=audience,
                outcome=AuditOutcome.ALLOWED,
                detail={"issuer": issuer, "expires_in": expires_in},
            )
        return ExchangedToken(
            access_token=token, audience=audience, issuer=issuer, expires_at=expires_at
        )

    def _verify_scope(self, token: ExchangedToken) -> None:
        """Check the credential we were given against the one we asked for.

        This is task 28's actual content. The parameter that requests a scope is
        advisory — RFC 8707 §2 only *recommends* that a server which cannot
        honour it answers `invalid_target`, and the server this project runs
        against neither honours it nor complains. A control built on the request
        would be a control that reports success when nothing happened.

        Two conditions, and the second is the interesting one:

        **The credential must name the target.** If it does not, whatever came
        back is for something else, and sending it upstream would at best fail
        confusingly and at worst succeed somewhere unintended.

        **It must not name another upstream this gateway brokers for.** That is
        the confused-deputy condition written out: a credential that opens two
        doors is not scoped to one, and an upstream that receives it can replay
        it against its neighbour as the caller. The measured Keycloak default —
        an exchange with no `audience` returns *every* audience the requester
        can reach — is exactly this failure, one missing config line away.

        Audiences that are not upstreams (`account`, the requester's own client
        id, whatever a given server adds) are ignored. The check is deliberately
        about *this gateway's* estate rather than about tidiness, so it has no
        false positives to tune away — which is what stops it being disabled.
        """
        audiences = _audiences_of(token.access_token)
        if audiences is None:
            # Opaque, or not a JWT. Nothing can be checked, and refusing would
            # rule out every authorization server that issues opaque tokens for
            # a property this gateway cannot observe either way. Said out loud
            # rather than passed over — see SECURITY.md.
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
        """Turn the authorization server's refusal into one of our errors.

        OAuth error bodies are small, defined by RFC 6749 §5.2, and contain no
        secret — the whole point of `error_description` is to be read by whoever
        is debugging. They go in the log, not into the message returned to the
        caller: an agent learns nothing useful from `invalid_target`, and
        somebody probing the gateway learns which audiences exist.
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

    Sits between the upstream client, which knows which upstream it is calling,
    and the exchanger, which knows how to obtain a credential for it. The
    upstream client therefore never touches an inbound token, never sees an
    issuer, and needs no branch for whether exchange is configured — it either
    has one of these or it has ``None``.
    """

    def __init__(self, exchanger: TokenExchanger) -> None:
        self._exchanger = exchanger

    async def authorization_for(
        self, upstream: str, audience: str, resource: str = ""
    ) -> str | None:
        """A ``Bearer`` value for this upstream, or ``None`` when there is no caller.

        ``None`` happens on the background health prober's requests, which have
        no principal because no user asked for them. That is a real gap and a
        deliberately scoped one: the correct answer is a client-credentials
        grant for the gateway's own service account, which needs a second grant
        type and belongs with the caching work in task 30. Until then a probe
        reaches an upstream uncredentialed, which the mock fleet accepts and a
        real upstream would not.

        It is safe *here* because a deployment with exchange configured also has
        ``ACP_AUTH_REQUIRED`` set, so every request-path call has a principal.
        The prober is the only caller that does not.
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
    """The `aud` of a JWT, or ``None`` when it is not one.

    Deliberately *not* verified. The signature is irrelevant to the question
    being asked: this credential arrived over TLS from a token endpoint the
    gateway authenticated to moments ago, and what is being read is not a trust
    decision but a scope one — "is this the thing I asked for". Verifying it
    would also be checking somebody else's audience, which is the upstream's
    job and not ours.

    ``None`` for anything unparseable, which the caller reports rather than
    treats as empty. An empty audience set and an unreadable token are different
    facts, and conflating them would turn "cannot check" into "checked, found
    nothing wrong".
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


def require_token_endpoints(issuers: IssuerRegistry) -> None:
    """Refuse to start when exchange is configured and an issuer cannot do it.

    At startup, before a port is bound, because the alternative is a gateway
    that serves happily and fails the first request from whichever authorization
    server happens to be the one without an endpoint. With several issuers that
    could be the tenant nobody tested.
    """
    missing = [r.issuer for r in issuers if not r.token_endpoint]
    if not missing:
        return
    msg = (
        f"token exchange is configured, but no token endpoint is known for: "
        f"{', '.join(sorted(missing))}. It is normally discovered from the issuer's "
        f"metadata — an explicit ACP_AUTH_JWKS_URL skips that discovery, in which "
        f"case set ACP_AUTH_TOKEN_ENDPOINT as well."
    )
    raise ConfigurationError(msg)
