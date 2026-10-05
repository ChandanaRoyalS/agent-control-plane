"""The two ways the model-driven agent reaches its tools.

Direct uses the gateway's own `UpstreamClient` with no controls, exposing tools under the
qualified names (ADR 0003) so the only difference is the gateway. Through the gateway uses the
official MCP client (ADR 0072); a held call is reported as held, not retried.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from mcp.client import Client
from mcp.shared.exceptions import MCPError
from mcp.types import InputRequiredResult, TextContent

from acp.demo.model_agent import Kind, Observation, Tool
from acp.exceptions import ACPError
from acp.upstream import UpstreamClient

SEPARATOR = "__"


class DirectCaller:
    """The agent and the upstreams, with nothing in between."""

    def __init__(self, upstreams: Sequence[UpstreamClient]) -> None:
        self._upstreams = {u.config.name: u for u in upstreams}

    async def tools(self) -> list[Tool]:
        found: list[Tool] = []
        for name, upstream in self._upstreams.items():
            listed = await upstream.list_tools()
            found.extend(
                Tool(
                    name=f"{name}{SEPARATOR}{tool.name}",
                    description=tool.description,
                    parameters=tool.input_schema,
                )
                for tool in listed.tools
            )
        return found

    async def call(self, name: str, arguments: Mapping[str, Any]) -> Observation:
        server, _, tool = name.partition(SEPARATOR)
        upstream = self._upstreams.get(server)
        if upstream is None or not tool:
            return Observation(Kind.FAILED, f"no tool named {name!r}")
        try:
            result = await upstream.call_tool(tool, arguments)
        except ACPError as exc:
            return Observation(Kind.FAILED, str(exc))
        text = "\n".join(block.text or "" for block in result.content)
        return Observation(Kind.FAILED if result.is_error else Kind.SERVED, text)


class GatewayCaller:
    """The agent behind the gateway, speaking through the official client."""

    def __init__(self, client: Client) -> None:
        self._client = client

    async def tools(self) -> list[Tool]:
        listed = await self._client.list_tools()
        return [
            Tool(
                name=tool.name,
                description=tool.description or "",
                parameters=dict(tool.input_schema),
            )
            for tool in listed.tools
        ]

    async def call(self, name: str, arguments: Mapping[str, Any]) -> Observation:
        try:
            result = await self._client.session.call_tool(
                name, dict(arguments), allow_input_required=True
            )
        except MCPError as exc:
            return Observation(Kind.REFUSED, exc.error.message, code=exc.error.code)
        if isinstance(result, InputRequiredResult):
            return Observation(Kind.HELD, "awaiting approval")
        text = "\n".join(b.text for b in result.content if isinstance(b, TextContent))
        return Observation(Kind.FAILED if result.is_error else Kind.SERVED, text)
