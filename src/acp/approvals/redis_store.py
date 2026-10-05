"""An approval store that outlives the process and is shared across replicas.

The in-memory store (`acp.approvals.store`) is correct for one gateway and
wrong for two: a caller who was told `input_required` by one replica and retries
against another is refused for a call a human approved, and a restart forgets
every pending decision. ADR 0066 names that a correctness bug rather than an
availability cut. This module is the fix: the same four operations against a
row in Redis, which every replica can reach.

**What a record is here.** One key per token, `acp:approval:<token>`, holding the
`ApprovalRequest` as JSON, with a Redis TTL set from the request's own expiry
plus a grace period. The grace is what keeps the state machine honest across
the boundary: an *expired* request must still be readable for as long as a late
retry or a late operator might ask about it, so that they get "expired" (which
`flow` and `operator` compute from the record) rather than "no such request".
After the grace Redis forgets it, which is the bound this store has instead of
`max_pending`: time, enforced by the database, rather than a count enforced by
eviction. A flood costs the flooder re-asks and costs Redis memory for one TTL.

**`decide` and `consume` are compare-and-set.** Two operators answering the
same token, or an operator's decision racing the retry that spends it, must
resolve to exactly one winner — the second answer sees the first. That is a
`WATCH`/`MULTI` transaction on the key: read, check the state is still what the
transition requires, write, and retry from the read if the key moved underneath.
The retry is bounded; a key that moves five times in a row is not a race, it is
something wrong, and the caller gets the current record rather than a loop.

**Listing is a set, not a scan.** `pending()` reads the members of
`acp:approval:pending`, which `create` adds to and `decide`/`consume` remove
from, then fetches those records in one round trip. A `SCAN` over the keyspace
would be O(every key in Redis), which on a shared instance is somebody else's
data too. Members whose record has expired out from under the set are dropped
from both on read.

**Every call is awaited.** `redis.asyncio` on the event loop, no thread hop, no
blocking client — the shape ADR 0053 made mandatory for anything on the request
path that waits on I/O.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any, Final

from redis.asyncio import Redis, WatchError

from acp.approvals.record import ApprovalRequest, State
from acp.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

KEY_PREFIX: Final = "acp:approval:"
PENDING_SET: Final = "acp:approval:pending"
GRACE_SECONDS: Final = 300.0
"""How long past its own expiry a record stays readable. Long enough that a
late operator sees "expired" and not "no such request" (ADR 0048 says why the
distinction matters); short enough that a flood is forgotten in minutes."""
MAX_CAS_ATTEMPTS: Final = 5
APPROVAL_STORE_SCHEMES: Final = ("redis://", "rediss://", "unix://")


def encode(request: ApprovalRequest) -> str:
    return json.dumps(asdict(request), separators=(",", ":"), sort_keys=True)


def decode(raw: bytes | str) -> ApprovalRequest:
    data = json.loads(raw)
    data["state"] = State(data["state"])
    return ApprovalRequest(**data)


def key_for(token: str) -> str:
    return KEY_PREFIX + token


class RedisApprovalStore:
    """`ApprovalStore` and `ApprovalReader`, against a Redis every replica shares."""

    def __init__(self, client: Redis, *, grace_seconds: float = GRACE_SECONDS) -> None:
        self._redis = client
        self._grace = grace_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisApprovalStore:
        """A store on the Redis at ``url`` (``redis://``, ``rediss://``, ``unix://``)."""
        return cls(Redis.from_url(url, **kwargs))

    async def ping(self) -> None:
        """Refuse to start a gateway whose approval store it cannot reach.

        A store that is configured and unreachable is worse than none: every
        gated call would be held with nothing to hold it in, and the first
        anyone learns of it is a caller waiting out a TTL for a decision that
        was never stored.
        """
        try:
            await self._redis.ping()
        except Exception as exc:
            await self.aclose()
            msg = f"the approval store at the configured Redis is unreachable: {exc}"
            raise ConfigurationError(msg) from exc

    async def aclose(self) -> None:
        await self._redis.aclose()

    # -- ApprovalStore -----------------------------------------------------------

    async def create(self, request: ApprovalRequest) -> None:
        ttl = max(1, int(request.expires_at - request.created_at + self._grace))
        async with self._redis.pipeline(transaction=True) as pipe:
            # NX: a token is 256 random bits and never reissued, so a collision
            # is a bug and must not silently overwrite somebody's record.
            pipe.set(key_for(request.token), encode(request), ex=ttl, nx=True)
            pipe.sadd(PENDING_SET, request.token)
            await pipe.execute()

    async def get(self, token: str) -> ApprovalRequest | None:
        raw = await self._redis.get(key_for(token))
        return None if raw is None else decode(raw)

    async def decide(
        self, token: str, *, approved: bool, reason: str = ""
    ) -> ApprovalRequest | None:
        return await self._transition(
            token,
            lambda held: held.decided(approved=approved, reason=reason),
            expect=State.PENDING,
            unlist=True,
        )

    async def consume(self, token: str) -> bool:
        spent = await self._transition(
            token, lambda held: held.consumed(), expect=State.APPROVED, unlist=False
        )
        return spent is not None

    async def _transition(
        self,
        token: str,
        step: Any,
        *,
        expect: State,
        unlist: bool,
    ) -> ApprovalRequest | None:
        """Compare-and-set one record from ``expect`` to what ``step`` makes it.

        Only a record in the expected state moves — the same rule as the
        in-memory store, for the same reason: refusing to re-decide is what
        makes `consume` mean anything. For `decide` a record that is already
        decided or spent is returned as it is, so a second operator sees the
        first operator's answer; for `consume` a record not in ``APPROVED`` is
        ``None``, which the caller reads as "not yours to spend".
        ``unlist`` is whether the move takes the token out of the pending set:
        a decision does; spending an already-decided record has nothing left
        to remove. On sustained contention the answer is the safe one for each
        caller — the current record for an operator, "not spent" for a retry.
        """
        key = key_for(token)
        for _ in range(MAX_CAS_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        await pipe.unwatch()  # type: ignore[no-untyped-call]
                        return None
                    held = decode(raw)
                    if held.state is not expect:
                        await pipe.unwatch()  # type: ignore[no-untyped-call]
                        return held if expect is State.PENDING else None
                    changed: ApprovalRequest = step(held)
                    ttl = await pipe.ttl(key)
                    pipe.multi()  # type: ignore[no-untyped-call]
                    if ttl and ttl > 0:
                        pipe.set(key, encode(changed), ex=ttl)
                    else:
                        pipe.set(key, encode(changed))
                    if unlist:
                        pipe.srem(PENDING_SET, token)
                    await pipe.execute()
                except WatchError:
                    continue
                else:
                    return changed
        logger.warning("approval.redis_contention", extra={"token_prefix": token[:8]})
        return await self.get(token) if expect is State.PENDING else None

    # -- ApprovalReader -------------------------------------------------------------

    async def pending(self) -> tuple[ApprovalRequest, ...]:
        members = await self._redis.smembers(PENDING_SET)
        tokens = sorted(m.decode() if isinstance(m, bytes) else str(m) for m in members)
        if not tokens:
            return ()
        raws = await self._redis.mget([key_for(t) for t in tokens])
        held: list[ApprovalRequest] = []
        gone: list[str] = []
        for token, raw in zip(tokens, raws, strict=True):
            if raw is None:
                gone.append(token)
                continue
            record = decode(raw)
            if record.state is State.PENDING:
                held.append(record)
            else:
                gone.append(token)
        if gone:
            await self._redis.srem(PENDING_SET, *gone)
        held.sort(key=lambda r: r.created_at)
        return tuple(held)
