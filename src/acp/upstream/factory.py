"""The only place the upstream layer stack is built (ADR 0006).

Order is a correctness property: retry outside the breaker counts attempts
individually, and retry outside the bulkhead means a backoff sleep holds no slot.
"""

from __future__ import annotations

from acp.upstream.breaker import CircuitBreaker, breaker_policy_for
from acp.upstream.cache import CachingUpstreamClient
from acp.upstream.cache import policy_for as cache_policy_for
from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig
from acp.upstream.guard import Bulkhead, GuardedUpstreamClient
from acp.upstream.protocol import Credentials, Upstream
from acp.upstream.resilient import RetryingUpstreamClient, policy_for


def build_upstream(client: UpstreamClient) -> Upstream:
    """Wrap a connected client in the guard, retry and cache layers."""
    config = client.config
    guarded = GuardedUpstreamClient(
        client,
        CircuitBreaker(config.name, breaker_policy_for(config)),
        Bulkhead(config.name, config.max_concurrency),
    )
    retrying = RetryingUpstreamClient(guarded, policy_for(config))
    # Caching outermost, so a hit skips retry, breaker and bulkhead.
    return CachingUpstreamClient(retrying, cache_policy_for(config))


async def connect_upstream(
    config: UpstreamConfig,
    credentials: Credentials | None = None,
    secret: str | None = None,
) -> Upstream:
    """Open a pool to ``config`` and return the fully wrapped upstream.

    ``credentials`` goes to the innermost layer so a credential is minted only for a
    request actually sent, never reused across retries (ADR 0019).
    """
    return build_upstream(await UpstreamClient.connect(config, credentials, secret))
