"""An approval store shared across replicas and restarts, in Redis (ADR 0066).

One JSON key per token, `acp:approval:<token>`, with a TTL of the request's expiry
plus a grace period so late callers see "expired", not "no such request".
`decide` and `consume` are bounded `WATCH`/`MULTI` compare-and-set, so exactly one
racing caller wins. `pending()` reads the `acp:approval:pending` set, never a
keyspace scan. All I/O is awaited on `redis.asyncio` (ADR 0053).
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any, Final

from redis.asyncio import Redis, WatchError

from acp.approvals.record import ApprovalRequest, State
from acp.exceptions import ConfigurationError
from acp.redis_url import REDIS_SCHEMES, client_for, unavailable

logger = logging.getLogger(__name__)

KEY_PREFIX: Final = "acp:approval:"
PENDING_SET: Final = "acp:approval:pending"
GRACE_SECONDS: Final = 300.0
"""Seconds a record stays readable past its expiry, so late callers see "expired" (ADR 0048)."""
MAX_CAS_ATTEMPTS: Final = 5
APPROVAL_STORE_SCHEMES: Final = REDIS_SCHEMES


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
        """A store on the Redis at ``url``, with the client from `acp.redis_url`."""
        return cls(client_for(url), **kwargs)

    async def ping(self) -> None:
        """Raise ``ConfigurationError`` at startup if the store is unreachable."""
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
        async with unavailable("approval"), self._redis.pipeline(transaction=True) as pipe:
            # NX: a token collision is a bug and must not overwrite a record.
            pipe.set(key_for(request.token), encode(request), ex=ttl, nx=True)
            pipe.sadd(PENDING_SET, request.token)
            await pipe.execute()

    async def get(self, token: str) -> ApprovalRequest | None:
        async with unavailable("approval"):
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

        Only a record in ``expect`` moves. Otherwise `decide` gets the record as it
        stands and `consume` gets ``None`` (not spent); the same on sustained
        contention. ``unlist`` removes the token from the pending set.
        """
        key = key_for(token)
        for _ in range(MAX_CAS_ATTEMPTS):
            async with unavailable("approval"), self._redis.pipeline(transaction=True) as pipe:
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
        async with unavailable("approval"):
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
            async with unavailable("approval"):
                await self._redis.srem(PENDING_SET, *gone)
        held.sort(key=lambda r: r.created_at)
        return tuple(held)
