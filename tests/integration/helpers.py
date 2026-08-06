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

from acp.upstream.envelope import routing_headers, with_envelope

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

    Always carries the 2026-07-28 envelope in ``params._meta``, because a
    request without one is not a valid request and a test that builds one is
    testing a shape no server accepts. This helper is the single place that
    knows the envelope, so the tests could not drift from the client even if
    someone wanted them to.
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": with_envelope(params, "acp-tests", "0"),
    }


def headers_for(body: Mapping[str, object]) -> dict[str, str]:
    """The routing headers a server will check this body against.

    Derived from the body rather than passed alongside it, so a test cannot
    accidentally assert agreement between two things it wrote separately.
    """
    method = body.get("method")
    if not isinstance(method, str):
        return {}
    params = body.get("params")
    return routing_headers(method, params if isinstance(params, Mapping) else None)
