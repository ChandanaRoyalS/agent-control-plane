"""The gateway's outbound half: talking to upstream MCP servers.

Hand-rolled over ``httpx`` so protocol failures from slow or hostile servers can be
observed and classified (ADR 0005). Resilience is layered as wrappers, stacked only
in :mod:`acp.upstream.factory` (ADR 0006).
"""

from acp.upstream.breaker import (
    BreakerPolicy,
    BreakerSnapshot,
    BreakerState,
    CircuitBreaker,
    breaker_policy_for,
)
from acp.upstream.cache import CachePolicy, CachingUpstreamClient
from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig
from acp.upstream.factory import build_upstream, connect_upstream
from acp.upstream.guard import Bulkhead, GuardedUpstreamClient
from acp.upstream.models import CallToolResult, ContentBlock, ListToolsResult, ToolDefinition
from acp.upstream.protocol import Upstream
from acp.upstream.resilient import RetryingUpstreamClient, policy_for
from acp.upstream.retry import RetryPolicy

__all__ = [
    "BreakerPolicy",
    "BreakerSnapshot",
    "BreakerState",
    "Bulkhead",
    "CachePolicy",
    "CachingUpstreamClient",
    "CallToolResult",
    "CircuitBreaker",
    "ContentBlock",
    "GuardedUpstreamClient",
    "ListToolsResult",
    "RetryPolicy",
    "RetryingUpstreamClient",
    "ToolDefinition",
    "Upstream",
    "UpstreamClient",
    "UpstreamConfig",
    "breaker_policy_for",
    "build_upstream",
    "connect_upstream",
    "policy_for",
]
