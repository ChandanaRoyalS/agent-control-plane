"""Helpers for driving mock upstreams in tests.

``asgi_client`` builds an in-process HTTP client against an ASGI app: no real
socket, no real network, no external process. That is the whole payoff of owning
the mock upstreams — the suite never depends on anything outside the repository,
so it is fast, deterministic, and works offline and in CI identically.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

import httpx
from starlette.applications import Starlette

MCP_URL = "/mcp"


@asynccontextmanager
async def asgi_client(app: Starlette) -> AsyncIterator[httpx.AsyncClient]:
    """An httpx client wired directly to an ASGI app via ``ASGITransport``."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://mock") as client:
        yield client


def rpc(
    method: str, params: Mapping[str, object] | None = None, request_id: int = 1
) -> dict[str, object]:
    """Build a JSON-RPC request body.

    ``params`` is a ``Mapping`` rather than a ``dict`` on purpose: ``dict`` is
    invariant in its value type, so a caller holding a ``dict[str, list[str]]``
    could not pass it to a ``dict[str, object]`` parameter. ``Mapping`` is
    covariant in its value type, which is what makes ordinary call sites work.
    """
    body: dict[str, object] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = dict(params)
    return body
