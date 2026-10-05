"""Fetch and cache the identity provider's JWKS signing keys.

The ``kid`` is attacker-controlled, so a miss triggers at most one refetch per
``min_refresh_interval``, and concurrent misses share one fetch under a lock. A token
without ``kid`` is accepted only when the set holds exactly one key; trying every key
would be an attacker-controlled signature-check multiplier.
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
"""Seconds a fetched document is trusted before a proactive refresh."""

DEFAULT_MIN_REFRESH_INTERVAL = 30.0
"""Minimum seconds between miss-triggered fetches; rate-limits attacker-triggered work."""

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
        """Return the verification key for this ``kid``, fetching if it is unknown.

        Raises:
            AuthenticationError: The key is unknown after any permitted refetch.
        """
        if self._stale():
            await self._refresh(reason="expired")

        key = self._select(kid)
        if key is not None:
            return key

        # Rotation and a forged `kid` look identical, hence the rate limit.
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
            # Re-check under the lock so waiters do not refetch. The `wanted` check matters
            # on rotation, where the interval may have elapsed for every waiter.
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
            # No stale fallback: unconfirmable keys would hide revocation. Unavailable, not
            # AuthenticationError, so an IdP outage is 503 rather than a 401 storm.
            msg = "cannot reach the identity provider's key set"
            raise IdentityProviderUnavailableError(msg, details={"url": self._url}) from exc
        return payload


def _parse(document: dict[str, Any], url: str) -> dict[str, Any]:
    """Turn a JWKS document into ``kid`` → key, parsed by PyJWT."""
    try:
        key_set = jwt.PyJWKSet.from_dict(document)
    except (jwt.PyJWKSetError, jwt.PyJWKError, KeyError, TypeError) as exc:
        msg = "the identity provider returned a key set this gateway cannot parse"
        raise IdentityProviderUnavailableError(msg, details={"url": url}) from exc

    keys: dict[str, Any] = {}
    for index, jwk in enumerate(key_set.keys):
        if jwk.public_key_use not in (None, "sig"):
            # RFC 7517 §4.2: never verify signatures with an `enc` key; absent `use` is ok.
            logger.debug("jwks.key_skipped", extra={"url": url, "kid": jwk.key_id, "use": "enc"})
            continue
        try:
            keys[jwk.key_id or f"__unnamed_{index}"] = jwk.key
        except jwt.PyJWKError:  # pragma: no cover - one bad key must not poison the set
            logger.warning("jwks.key_unusable", extra={"url": url, "kid": jwk.key_id})

    if not keys:
        msg = "the identity provider's key set contains no usable keys"
        raise IdentityProviderUnavailableError(msg, details={"url": url})
    return keys
