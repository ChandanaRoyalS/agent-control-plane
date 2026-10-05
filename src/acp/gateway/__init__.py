"""The gateway's inbound half: the MCP server agents connect to.

Built on the MCP SDK for client compatibility, unlike the hand-rolled ``acp.upstream``
(ADR 0005).
"""

from acp.gateway.registry import Catalogue, UpstreamRegistry
from acp.gateway.server import build_app, build_server

__all__ = ["Catalogue", "UpstreamRegistry", "build_app", "build_server"]
