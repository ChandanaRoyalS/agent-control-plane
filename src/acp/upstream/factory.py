"""Assembling the layers that make up one usable upstream.

Kept in its own module, and deliberately the only place the stack is built.
Composition order is a correctness property here rather than a matter of taste
— retry outside the breaker means attempts are counted individually, retry
outside the bulkhead means a backoff sleep does not hold a slot — and an order
that only exists implicitly at each call site is one that will eventually be
written differently in two of them.
"""

from __future__ import annotations

from acp.upstream.breaker import CircuitBreaker, breaker_policy_for
from acp.upstream.cache import CachingUpstreamClient
from acp.upstream.cache import policy_for as cache_policy_for
from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig
from acp.upstream.guard import Bulkhead, GuardedUpstreamClient
from acp.upstream.protocol import Upstream
from acp.upstream.resilient import RetryingUpstreamClient, policy_for


def build_upstream(client: UpstreamClient) -> Upstream:
    """Wrap a connected client in the guard and retry layers.

    Takes an already-built client so tests can inject a transport, which is the
    same reason ``UpstreamClient`` takes one.
    """
    config = client.config
    guarded = GuardedUpstreamClient(
        client,
        CircuitBreaker(config.name, breaker_policy_for(config)),
        Bulkhead(config.name, config.max_concurrency),
    )
    retrying = RetryingUpstreamClient(guarded, policy_for(config))
    # Caching outermost, so a hit costs nothing: no retry bookkeeping, no
    # breaker check, no bulkhead slot. An answer the gateway already holds
    # should not walk through three layers of failure handling to be returned.
    return CachingUpstreamClient(retrying, cache_policy_for(config))


async def connect_upstream(config: UpstreamConfig) -> Upstream:
    """Open a pool to ``config`` and return the fully wrapped upstream."""
    return build_upstream(await UpstreamClient.connect(config))
