"""Mock upstream A — a document and ticketing service.

Three tools with distinct argument shapes, so catalog-merge and argument-level
policy tests (Phase 3) have something realistic to exercise. ``search`` is
deliberately duplicated on mock B with a different implementation, to exercise
the gateway's namespace-collision handling (ADR 0003) from day one.
"""

from __future__ import annotations

import hashlib
from typing import Any

from starlette.applications import Starlette

from acp.mocks.jsonrpc import CallToolResult, TextContent
from acp.mocks.server import MockTool, build_mock_app

# A small fixed "document store" so results are deterministic and inspectable
# in tests — no randomness, no clock, no filesystem.
_DOCUMENTS: dict[str, str] = {
    "runbooks/deploy.md": "# Deploy runbook\n\n1. Tag a release.\n2. Run the deploy workflow.",
    "policies/data-retention.md": "Logs are retained for 90 days, then deleted.",
}


def _read_document(arguments: dict[str, Any]) -> CallToolResult:
    path = arguments.get("path")
    if not isinstance(path, str):
        return CallToolResult(
            content=[TextContent(text="`path` is required and must be a string")],
            is_error=True,
        )
    content = _DOCUMENTS.get(path)
    if content is None:
        return CallToolResult(
            content=[TextContent(text=f"no such document: {path}")], is_error=True
        )
    return CallToolResult(content=[TextContent(text=content)])


def _search(arguments: dict[str, Any]) -> CallToolResult:
    query = str(arguments.get("query", ""))
    limit = int(arguments.get("limit", 10))
    matches = [path for path, text in _DOCUMENTS.items() if query.lower() in text.lower()][:limit]
    summary = ", ".join(matches) if matches else "no matches"
    return CallToolResult(content=[TextContent(text=f"mock-a search results: {summary}")])


def _create_ticket(arguments: dict[str, Any]) -> CallToolResult:
    title = arguments.get("title")
    priority = arguments.get("priority", "normal")
    if not isinstance(title, str) or not title:
        return CallToolResult(
            content=[TextContent(text="`title` is required and must be a non-empty string")],
            is_error=True,
        )
    # Deterministic fake ID derived from the title, not a counter or a clock.
    # Uses hashlib rather than the built-in hash(): Python randomises string
    # hashing per process (PYTHONHASHSEED), so hash() would produce a different
    # ID on every run and any test asserting on a ticket ID would pass locally
    # and fail in CI. hashlib is stable across processes and machines.
    digest = hashlib.sha256(title.encode()).hexdigest()
    ticket_id = f"TICKET-{int(digest[:8], 16) % 100000:05d}"
    return CallToolResult(
        content=[TextContent(text=f"created {ticket_id} (priority={priority}): {title}")]
    )


TOOLS: list[MockTool] = [
    MockTool(
        name="read_document",
        description="Read a document by its path.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        handler=_read_document,
    ),
    MockTool(
        name="search",
        description="Search documents by keyword.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
        handler=_search,
    ),
    MockTool(
        name="create_ticket",
        description="File a ticket. NOT idempotent to retry blindly — see ADR 0003.",
        input_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "priority": {"type": "string", "enum": ["low", "normal", "high"]},
            },
            "required": ["title"],
        },
        handler=_create_ticket,
    ),
]

app: Starlette = build_mock_app("mock-a", TOOLS)


if __name__ == "__main__":  # pragma: no cover — exercised via docker-compose, not pytest
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9101)
