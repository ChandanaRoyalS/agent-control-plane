"""The gateway's outbound half: talking to upstream MCP servers.

Hand-rolled over ``httpx`` rather than built on the MCP SDK — see
``docs/decisions/0005-hybrid-protocol-layer.md``. The short version: this side
talks to servers that are expected to be slow, broken, or hostile, and it needs
to *observe* protocol failures and classify them rather than have a library
raise on them. The inbound half (agent to gateway) has the opposite
requirements and uses the SDK.

Resilience is layered as wrappers around the client rather than folded into it
— see ``docs/decisions/0006-layer-resilience-as-wrappers.md`` and
:mod:`acp.upstream.factory`, which is the single place the layers are stacked.
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
