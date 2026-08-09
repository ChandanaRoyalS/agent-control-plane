"""Holding an exchanged credential, and the one line that decides whether that is safe.

Task 27 minted a credential per call and cached nothing, with a test asserting
it. This is that test changing — deliberately, with the key argued over, rather
than a behaviour nobody noticed.

**The key is the whole task.** Everything else here is a dictionary with a size
limit. Get the key wrong and this is a privilege escalation with excellent p99:
key on the upstream alone and alice's credential is served to bob; key on the
*agent* rather than the human and the same leak happens more quietly, because
both requests genuinely arrive from `agent-7`. Neither mistake fails a
functional test. Both would pass a load test beautifully.

**So the key is the request, not a model of the request.** An exchange is a pure
function of what is sent to the token endpoint: the subject token, the audience,
the resource indicator, and this gateway's own client credentials. Two requests
that send the same thing get the same answer. So the key is a digest of the
subject token plus the audience and resource — and the correctness argument is
one sentence with nothing left to reason about.

The alternative was to key on the *claims* — issuer, subject, actor, scopes —
which is what "cache per principal" naturally suggests. It requires deciding
which claims the authorization server might have used to decide what to put in
the token, and being wrong about that is invisible. Keycloak's realm here maps
`sub` and `act` and nothing else; a different server might scope by `azp`, by
the subject token's own scopes, by a claim nobody here has heard of. A key
derived from the request cannot be wrong about any of them, because it does not
guess.

**A digest, never the token.** Task 27's invariant is that the inbound token
exists in one place with one reader. Using it as a dictionary key would put it
in a second, and a cache is a structure whose whole purpose is to outlive the
request. SHA-256 of it is not a credential and cannot be replayed.
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio

if TYPE_CHECKING:  # pragma: no cover
    # Type-only, because `exchange` imports this module for the cache itself and
    # a runtime import here would close the loop. Nothing in this file *calls*
    # anything on the class beyond `expired()`, which is exactly the amount of
    # coupling a cache should have to the thing it holds.
    from acp.identity.exchange import ExchangedToken

logger = logging.getLogger(__name__)

DEFAULT_MAX_ENTRIES = 1024
"""Ceiling on cached credentials, and it is a security limit before it is a
memory one.

Unbounded, this grows with the number of distinct (token, upstream) pairs the
gateway has ever seen — which an unauthenticated attacker cannot influence, but
an authenticated one with a token mint can: obtain tokens in a loop, call once
with each, and every one is retained until it expires. A bound turns that into
eviction of somebody else's entry, which costs an exchange rather than the
process.
"""


@dataclass(frozen=True, slots=True)
class CredentialKey:
    """What makes two exchange requests the same request.

    Every field is something the token endpoint sees. Nothing here is a guess
    about what the authorization server does with them.
    """

    subject_digest: str
    audience: str
    resource: str

    @classmethod
    def of(cls, subject_token: str, audience: str, resource: str) -> CredentialKey:
        return cls(
            # Hex rather than raw bytes so the key prints safely if it ever ends
            # up in a debugger, a log line, or an exception message. It is a
            # one-way function of a credential, not the credential.
            subject_digest=hashlib.sha256(subject_token.encode()).hexdigest(),
            audience=audience,
            resource=resource,
        )

    @property
    def short(self) -> str:
        """Twelve characters, for logs. Enough to tell two keys apart in a trace
        and useless for anything else."""
        return self.subject_digest[:12]


class CredentialCache:
    """Exchanged credentials, held until shortly before they expire.

    Bounded and least-recently-used. **Single-flight**: concurrent misses for the
    same key produce one exchange, not one each — the same defect the JWKS cache
    shipped with in task 22, where twenty concurrent misses produced twenty-one
    fetches. Here the consequence is worse than wasted work: a burst of calls
    from one agent would turn into a burst of token requests, and an
    authorization server that rate-limits the gateway takes the whole estate
    down rather than one caller.
    """

    def __init__(self, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._entries: OrderedDict[CredentialKey, ExchangedToken] = OrderedDict()
        self._max_entries = max_entries
        # One lock per key, created on demand. A single global lock would
        # serialise every exchange in the gateway behind the slowest one, which
        # is a latency bug wearing a correctness costume.
        self._locks: dict[CredentialKey, anyio.Lock] = {}
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: CredentialKey) -> ExchangedToken | None:
        """A live credential for this key, or ``None``.

        Expiry is judged against ``DEFAULT_EXPIRY_SKEW`` — a token treated as
        good here and expired by the time the upstream reads it fails *after*
        the side effect may have happened, which is the worst available ordering.
        """
        token = self._entries.get(key)
        if token is None:
            return None
        if token.expired():
            # Dropped rather than returned-and-refreshed. A caller that receives
            # an expired credential has no way to tell it apart from a live one.
            del self._entries[key]
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
        """The lock that makes concurrent misses collapse into one exchange."""
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
