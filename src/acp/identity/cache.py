"""Cache for exchanged credentials, keyed so one caller's credential never reaches another.

An exchange is a pure function of what is sent to the token endpoint, so the key is a
SHA-256 digest of the subject token plus audience and resource. Keying on claims would
guess what the authorization server uses; keying on the agent would leak across humans.
The digest keeps the inbound token itself out of the cache.
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio

if TYPE_CHECKING:  # pragma: no cover
    # Type-only: `exchange` imports this module, so a runtime import would be circular.
    from acp.identity.exchange import ExchangedToken

logger = logging.getLogger(__name__)

DEFAULT_MAX_ENTRIES = 1024
"""Ceiling on cached credentials; a security bound against a caller minting tokens in a loop."""


@dataclass(frozen=True, slots=True)
class CredentialKey:
    """Identity of an exchange request: only fields the token endpoint sees."""

    subject_digest: str
    audience: str
    resource: str

    @classmethod
    def of(cls, subject_token: str, audience: str, resource: str) -> CredentialKey:
        return cls(
            # Hex so the key prints safely; a one-way digest, not the credential.
            subject_digest=hashlib.sha256(subject_token.encode()).hexdigest(),
            audience=audience,
            resource=resource,
        )

    @property
    def short(self) -> str:
        """First twelve hex characters, for logs."""
        return self.subject_digest[:12]


class CredentialCache:
    """Bounded LRU of exchanged credentials, held until shortly before expiry.

    Single-flight: concurrent misses for one key produce one exchange, so a burst
    cannot trip the authorization server's rate limit for the whole gateway.
    """

    def __init__(self, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._entries: OrderedDict[CredentialKey, ExchangedToken] = OrderedDict()
        self._max_entries = max_entries
        # Per-key locks: a global lock would serialise every exchange behind the slowest.
        self._locks: dict[CredentialKey, anyio.Lock] = {}
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: CredentialKey) -> ExchangedToken | None:
        """Return a live credential for this key, or ``None``.

        Expiry uses ``DEFAULT_EXPIRY_SKEW`` so a token cannot expire in flight to the upstream.
        """
        token = self._entries.get(key)
        if token is None:
            return None
        if token.expired():
            # Dropped, with its lock, so locks do not accumulate per subject token.
            del self._entries[key]
            self._locks.pop(key, None)
            return None
        self._entries.move_to_end(key)
        return token

    def put(self, key: CredentialKey, token: ExchangedToken) -> None:
        self._entries[key] = token
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            evicted, _ = self._entries.popitem(last=False)
            self._locks.pop(evicted, None)
            logger.debug(
                "auth.credential_evicted",
                extra={"audience": evicted.audience, "key": evicted.short},
            )

    def lock_for(self, key: CredentialKey) -> anyio.Lock:
        """Return the per-key lock that collapses concurrent misses."""
        lock = self._locks.get(key)
        if lock is None:
            lock = anyio.Lock()
            self._locks[key] = lock
        return lock

    def record(self, *, hit: bool) -> None:
        if hit:
            self.hits += 1
        else:
            self.misses += 1

    def clear(self) -> None:
        self._entries.clear()
        self._locks.clear()
