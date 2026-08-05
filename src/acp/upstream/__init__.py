"""The gateway's outbound half: talking to upstream MCP servers.

Hand-rolled over ``httpx`` rather than built on the MCP SDK — see
``docs/decisions/0005-hybrid-protocol-layer.md``. The short version: this side
talks to servers that are expected to be slow, broken, or hostile, and it needs
to *observe* protocol failures and classify them rather than have a library
raise on them. The inbound half (agent to gateway) has the opposite
requirements and uses the SDK.
"""

from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig
from acp.upstream.models import CallToolResult, ContentBlock, ToolDefinition

__all__ = [
    "CallToolResult",
    "ContentBlock",
    "ToolDefinition",
    "UpstreamClient",
    "UpstreamConfig",
]
