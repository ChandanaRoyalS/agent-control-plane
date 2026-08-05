"""The gateway's inbound half: the MCP server agents connect to.

Built on the MCP SDK (ADR 0005), in contrast to ``acp.upstream`` which is
hand-rolled over httpx. The two halves have opposite requirements: inbound
optimises for compatibility with clients we do not control, outbound for
control over servers that may misbehave.
"""

from acp.gateway.registry import Catalogue, UpstreamRegistry
from acp.gateway.server import build_app, build_server

__all__ = ["Catalogue", "UpstreamRegistry", "build_app", "build_server"]
