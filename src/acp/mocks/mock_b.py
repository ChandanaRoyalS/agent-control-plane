"""Mock upstream B — a chat and directory service.

``search`` here deliberately collides in name with mock A's ``search`` but has
a different schema and a different implementation, which is the point: the
gateway must namespace both as distinct tools (``mock-a__search`` and
``mock-b__search``, per ADR 0003) rather than the second silently shadowing
the first.
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette

from acp.mocks.jsonrpc import CallToolResult, TextContent
from acp.mocks.server import MockTool, build_mock_app

_CHANNELS: dict[str, list[str]] = {
    "general": ["welcome to the team", "standup is at 10am"],
    "incidents": ["payment API returned 500s for 4 minutes at 14:02 UTC"],
}


def _search(arguments: dict[str, Any]) -> CallToolResult:
    # Deliberately different argument shape from mock-a's `search` (channel
    # instead of limit) — the collision is in *name* only, not in behaviour.
    query = str(arguments.get("query", ""))
    channel = arguments.get("channel")
    channels = [channel] if isinstance(channel, str) else list(_CHANNELS)
    hits = [
        f"#{ch}: {msg}"
        for ch in channels
        for msg in _CHANNELS.get(ch, [])
        if query.lower() in msg.lower()
    ]
    summary = "; ".join(hits) if hits else "no matches"
    return CallToolResult(content=[TextContent(text=f"mock-b search results: {summary}")])


def _summarize(arguments: dict[str, Any]) -> CallToolResult:
    channel = arguments.get("channel")
    if not isinstance(channel, str) or channel not in _CHANNELS:
        return CallToolResult(
            content=[TextContent(text=f"unknown channel: {channel!r}")], is_error=True
        )
    messages = _CHANNELS[channel]
    return CallToolResult(
        content=[TextContent(text=f"#{channel} ({len(messages)} messages): {'; '.join(messages)}")]
    )


def _list_channels(_arguments: dict[str, Any]) -> CallToolResult:
    return CallToolResult(content=[TextContent(text=", ".join(sorted(_CHANNELS)))])


TOOLS: list[MockTool] = [
    MockTool(
        name="search",
        description="Search chat messages, optionally scoped to a channel.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "channel": {"type": "string"},
            },
            "required": ["query"],
        },
        handler=_search,
    ),
    MockTool(
        name="summarize",
        description="Summarize all messages in a channel.",
        input_schema={
            "type": "object",
            "properties": {"channel": {"type": "string"}},
            "required": ["channel"],
        },
        handler=_summarize,
    ),
    MockTool(
        name="list_channels",
        description="List all known channels.",
        input_schema={"type": "object", "properties": {}},
        handler=_list_channels,
    ),
]

app: Starlette = build_mock_app("mock-b", TOOLS)


if __name__ == "__main__":  # pragma: no cover — exercised via docker-compose, not pytest
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9102)
