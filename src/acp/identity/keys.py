"""Fetching and caching the identity provider's signing keys.

A JWKS document is the set of public keys an authorization server signs with.
Verifying a token means finding the one named by its ``kid`` header — which
sounds like a cache with a TTL and is, until you look at who controls the input.

**The ``kid`` comes from the attacker.** A cache that refetches on every miss
turns "send tokens with random ``kid`` values" into an unauthenticated request
amplifier pointed at the identity provider, with the gateway paying the latency.
So a miss may trigger at most one refetch per ``min_refresh_interval``, and
outside that window a miss is simply a miss. Rotation is still picked up
promptly; a flood is not amplified.

**One fetch, not fifty.** When a key genuinely rotates, every in-flight request
misses at the same instant. Without a lock they would all fetch, which is the
same thundering herd the bulkhead exists to prevent one layer down — so the
first waiter fetches and the rest wait on it.

**No ``kid``, no guessing.** A token with no ``kid`` is accepted only when the
document holds exactly one key. Trying each key in turn would work, and it would
also be a signature oracle that costs one public-key operation per key per
attempt — an attacker-controlled multiplier on the most expensive thing this
gateway does.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import anyio
import httpx
import jwt

from acp.exceptions import AuthenticationError, IdentityProviderUnavailableError

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = 600.0
"""How long a fetched document is trusted before a proactive refresh.

Ten minutes. Long enough that key lookup is free in the normal case, short
enough that a planned rotation is picked up without anyone presenting a token
signed by the new key first.
"""

DEFAULT_MIN_REFRESH_INTERVAL = 30.0
"""Floor between two fetches triggered by a cache miss. See the module
docstring: this number is a rate limit on attacker-triggered work."""

DEFAULT_TIMEOUT = 5.0


class JwksCache:
    """The identity provider's public keys, kept fresh without being a lever."""

    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient | None = None,
        ttl: float = DEFAULT_CACHE_TTL,
        min_refresh_interval: float = DEFAULT_MIN_REFRESH_INTERVAL,
        timeout: float = DEFAULT_TIMEOUT,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._url = url
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._ttl = ttl
        self._min_refresh_interval = min_refresh_interval
        self._clock = clock or time.monotonic
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = anyio.Lock()

    @property
    def url(self) -> str:
        return self._url

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- lookup ------------------------------------------------------------

    async def key_for(self, kid: str | None) -> Any:
        """The verification key for this ``kid``, fetching if it is unknown."""
        if self._stale():
            await self._refresh(reason="expired")

        key = self._select(kid)
        if key is not None:
            return key

        # A miss on a document we already hold means either a rotation we have
        # not seen or a `kid` nobody ever issued. Both look identical from here,
        # which is exactly why the refetch is rate limited rather than
        # unconditional.
        if self._may_retry():
            await self._refresh(reason="unknown_kid", wanted=kid)
            key = self._select(kid)
            if key is not None:
                return key

        raise AuthenticationError(
            "the token was signed by a key this gateway does not recognise",
            details={"kid": kid} if kid else None,
        )

    def _select(self, kid: str | None) -> Any:
        if kid is not None:
            return self._keys.get(kid)
        # No `kid`. Unambiguous only when there is one key to mean.
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    # -- refresh -----------------------------------------------------------

    def _stale(self) -> bool:
        return self._fetched_at is None or (self._clock() - self._fetched_at) >= self._ttl

    def _may_retry(self) -> bool:
        return (
            self._last_attempt is None
            or (self._clock() - self._last_attempt) >= self._min_refresh_interval
        )

    async def _refresh(self, *, reason: str, wanted: str | None = None) -> None:
        async with self._lock:
            # Everything is re-checked inside the lock, because everyone who
            # queued behind the first fetcher is now holding a fresh document
            # and refetching once per waiter is the herd this lock exists to
            # stop.
            #
            # The `wanted` check is the one that actually does that work, and it
            # is not the same as the rate limit. On a real rotation the interval
            # may well have elapsed for every waiter — they arrived together
            # precisely because the key changed — so the only thing that
            # distinguishes "I still need a fetch" from "somebody just fetched
            # what I wanted" is whether the key is now here.
            if wanted is not None and self._select(wanted) is not None:
                return
            if reason == "expired" and not self._stale():
                return
            if reason == "unknown_kid" and not self._may_retry():
                return

            self._last_attempt = self._clock()
            document = await self._fetch()
            self._keys = _parse(document, self._url)
            self._fetched_at = self._clock()
            logger.info(
                "jwks.refreshed",
                extra={"url": self._url, "reason": reason, "keys": len(self._keys)},
            )

    async def _fetch(self) -> dict[str, Any]:
        try:
            response = await self._client.get(self._url)
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Deliberately not falling back to a stale document. A gateway that
            # keeps validating tokens against keys it can no longer confirm is
            # a gateway that cannot be told a key was revoked — and revocation
            # is the one thing key rotation exists to make possible.
            #
            # `IdentityProviderUnavailableError`, not `AuthenticationError`.
            # The caller's token may be perfectly good; we simply cannot check
            # it. Conflating the two answers 401 to a dependency outage and
            # sends the whole fleet to re-authenticate against a server that is
            # already down.
            msg = "cannot reach the identity provider's key set"
            raise IdentityProviderUnavailableError(msg, details={"url": self._url}) from exc
        return payload


def _parse(document: dict[str, Any], url: str) -> dict[str, Any]:
    """Turn a JWKS document into ``kid`` → key.

    Parsed by PyJWT rather than by hand. A JWK is a dense little format with
    base64url-encoded big integers in it, and writing a second parser for it
    would be inventing a way to disagree with the library that does the actual
    verification.
    """
    try:
        key_set = jwt.PyJWKSet.from_dict(document)
    except (jwt.PyJWKSetError, jwt.PyJWKError, KeyError, TypeError) as exc:
        msg = "the identity provider returned a key set this gateway cannot parse"
        raise IdentityProviderUnavailableError(msg, details={"url": url}) from exc

    keys: dict[str, Any] = {}
    for index, jwk in enumerate(key_set.keys):
        try:
            keys[jwk.key_id or f"__unnamed_{index}"] = jwk.key
        except jwt.PyJWKError:  # pragma: no cover - one bad key must not poison the set
            logger.warning("jwks.key_unusable", extra={"url": url, "kid": jwk.key_id})

    if not keys:
        msg = "the identity provider's key set contains no usable keys"
        raise IdentityProviderUnavailableError(msg, details={"url": url})
    return keys
