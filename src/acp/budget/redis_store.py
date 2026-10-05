"""Budgets every replica charges against the same bucket and the same tally.

The in-memory limiter and quota are per process, and the threat model
(section 6.6) names the consequence: a replicated fleet multiplies every limit
by the number of processes. Three gateways behind one load balancer hand out
three bursts and three daily quotas to the same payer, and which one a call
drains is up to the balancer. This module keeps one bucket and one tally per
payer in Redis, so the limit configured is the limit enforced, however many
gateways enforce it.

**One script, one round trip, atomic.** `charge` runs a Lua script that
refills the bucket to ``now``, reads the window's tally, checks *both* against
the cost, and only then debits *both* — ADR 0044 §3's "check both, then debit
both", which on one process was four calls with nothing awaited between them
and across replicas is only true inside a script. Redis runs scripts without
interleaving, so two replicas charging the same payer at the same instant are
serialised by the server, not raced by the clients. ADR 0066 chose
`WATCH`/`MULTI` over Lua for approvals; the trade flips here, and ADR 0067
says why: an approval key moves a few times in its life, a payer's bucket
moves on every call, and an optimistic transaction on a hot key is a retry
loop under exactly the load a rate limiter exists for.

**The arithmetic is the in-memory arithmetic.** The bucket is `TokenBucket`'s:
start full, refill at the rate up to the capacity, never go backwards when
the clock does. The window is `QuotaCounter`'s: clock-aligned,
``floor(now / window)``, reset at absolute boundaries. The two Python classes
remain the specification, and the contract tests run the same cases against
both keepers so that they cannot drift apart unnoticed.

**One clock.** The in-memory limiter refills on a monotonic clock so that a
wall-clock step cannot hand out or withhold burst. Replicas share no monotonic
clock, so this keeper refills on the wall clock the caller passes — the one
the quota window already used. A step on one replica's clock misgrants or
withholds at most one capacity, once, on that replica; the elapsed-time guard
still never removes tokens for a backwards step.

**Time is the bound.** A bucket key expires when the bucket would be full
again, because a missing bucket *is* a full one — that is what "start full on
first sight" means in a store. A tally key is the window index, and expires
when the window ends. Neither needs `max_principals`: a payer who is never
seen again costs Redis memory for one refill or one window, and nobody is
evicted to make room, which was the eviction-order argument of
`RateLimiter._bucket` with nothing left to defend.
"""

from __future__ import annotations

import math
from typing import Any, Final

from redis.asyncio import Redis

from acp.exceptions import ConfigurationError, QuotaExceededError, RateLimitExceededError
from acp.redis_url import client_for, unavailable

RATE_PREFIX: Final = "acp:budget:rate:"
QUOTA_PREFIX: Final = "acp:budget:quota:"

OK: Final = b"ok"
RATE: Final = b"rate"
QUOTA: Final = b"quota"

CHARGE_SCRIPT: Final = """
local rate_key, quota_key = KEYS[1], KEYS[2]
local cost = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill = tonumber(ARGV[3])
local limit = tonumber(ARGV[4])
local window = tonumber(ARGV[5])
local now = tonumber(ARGV[6])

-- The bucket, refilled to now. Absent means full: see the module docstring.
local tokens = capacity
if capacity > 0 then
  local held = redis.call('HMGET', rate_key, 'tokens', 'updated_at')
  if held[1] then
    local elapsed = now - tonumber(held[2])
    if elapsed < 0 then elapsed = 0 end
    tokens = math.min(capacity, tonumber(held[1]) + elapsed * refill)
  end
end

-- The window's tally. The key already names the window, so a stale one is
-- simply a different key that has expired or will.
local used = 0
if limit > 0 then
  used = tonumber(redis.call('GET', quota_key) or '0')
end

-- Check both before debiting either.
if capacity > 0 and tokens < cost then
  local retry = -1
  if refill > 0 then retry = (cost - tokens) / refill end
  return {'rate', tostring(retry), tostring(tokens), tostring(capacity)}
end
if limit > 0 and used + cost > limit then
  local resets_at = (math.floor(now / window) + 1) * window
  local left = limit - used
  if left < 0 then left = 0 end
  return {'quota', tostring(resets_at - now), tostring(left), tostring(limit)}
end

-- Then debit both.
if capacity > 0 then
  local left = tokens - cost
  redis.call('HSET', rate_key, 'tokens', tostring(left), 'updated_at', tostring(now))
  if refill > 0 then
    -- Forget the bucket once it would be full again; a full bucket and no
    -- bucket are the same thing. At least one second, so a bucket that is
    -- nearly full is not forgotten before the next call reads it.
    redis.call('EXPIRE', rate_key, math.max(1, math.ceil((capacity - left) / refill)))
  end
end
if limit > 0 then
  redis.call('INCRBYFLOAT', quota_key, cost)
  local resets_at = (math.floor(now / window) + 1) * window
  redis.call('EXPIRE', quota_key, math.max(1, math.ceil(resets_at - now)))
end
return {'ok'}
"""


def rate_key(payer: str) -> str:
    return RATE_PREFIX + payer


def quota_key(payer: str, now: float, window_seconds: float) -> str:
    """The tally for the window containing ``now`` — the index is in the key,
    so a window's spend is a value that expires, not a field that resets."""
    return f"{QUOTA_PREFIX}{payer}:{math.floor(now / window_seconds)}"


class RedisBudgets:
    """`Budgets`, against a Redis every replica shares.

    ``capacity`` and ``refill_per_second`` describe the rate limit; ``None``
    for ``capacity`` means there is no rate limit. ``limit`` and
    ``window_seconds`` describe the quota; ``None`` for ``limit`` means there
    is none. The values travel with every charge rather than being stored, so
    a configuration change takes effect at the next call and two replicas
    with different settings are a misconfiguration this store cannot hide —
    whichever answers, answers with its own numbers.
    """

    def __init__(
        self,
        client: Redis,
        *,
        capacity: float | None,
        refill_per_second: float = 0.0,
        limit: float | None,
        window_seconds: float = 1.0,
    ) -> None:
        if capacity is None and limit is None:
            msg = "a budget store with neither a rate limit nor a quota has nothing to charge"
            raise ValueError(msg)
        self._redis = client
        self._capacity = capacity
        self._refill = refill_per_second
        self._limit = limit
        self._window = window_seconds
        self._charge = client.register_script(CHARGE_SCRIPT)

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisBudgets:
        """With the timeouts and pool every store here has (`acp.redis_url`)."""
        return cls(client_for(url), **kwargs)

    @property
    def capacity(self) -> float | None:
        return self._capacity

    @property
    def limit(self) -> float | None:
        return self._limit

    async def ping(self) -> None:
        """Refuse to start a gateway whose budgets it cannot reach.

        A configured, unreachable store would refuse every charged call with
        a connection error dressed as an internal failure — or, worse, be
        made to fail open. Startup is where somebody is watching.
        """
        try:
            await self._redis.ping()
        except Exception as exc:
            await self.aclose()
            msg = f"the budget store at the configured Redis is unreachable: {exc}"
            raise ConfigurationError(msg) from exc

    async def aclose(self) -> None:
        await self._redis.aclose()

    async def charge(self, payer: str, cost: float, *, mono: float, wall: float) -> None:
        """Check both budgets and debit both, in one step on the server.

        ``mono`` is accepted for the protocol's sake and unused: replicas share
        no monotonic clock, so the bucket refills on ``wall`` (module
        docstring).
        """
        del mono
        async with unavailable("budget"):
            answer: list[bytes] = await self._charge(
                keys=[rate_key(payer), quota_key(payer, wall, self._window)],
                args=[
                    cost,
                    self._capacity if self._capacity is not None else 0,
                    self._refill,
                    self._limit if self._limit is not None else 0,
                    self._window,
                    wall,
                ],
            )
        kind = answer[0]
        if kind == OK:
            return
        retry_after, remaining, limit = (float(x) for x in answer[1:])
        details = {
            # -1 is the script's "never": a bucket that does not refill.
            "retry_after": retry_after if retry_after >= 0 else float("inf"),
            "remaining": remaining,
            "limit": limit,
        }
        if kind == RATE:
            raise RateLimitExceededError("rate limit exceeded; slow down", details=details)
        raise QuotaExceededError("quota exceeded for the current window", details=details)
