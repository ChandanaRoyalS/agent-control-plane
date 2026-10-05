"""The console routes, on the admin listener behind the operator credential.

Never on the gateway's listener, since the stream carries every principal's
activity (ADR 0049). The page reads the SSE stream with `fetch()` and an
`Authorization` header, because `EventSource` cannot set headers and a query-string
secret would leak into history and logs.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from acp.approvals.operator import matches_credential
from acp.console.hub import TraceHub
from acp.console.page import PAGE

CONSOLE_PATH = "/console"
STREAM_PATH = "/console/stream"

KEEPALIVE_SECONDS = 15.0
"""Seconds between SSE comment lines on an idle stream, so proxies and NAT keep it open."""


def _authorized(request: Request, credential: str) -> bool:
    """Whether this request carries the operator credential (constant-time compare)."""
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return matches_credential(presented, credential)


def _unauthorized() -> Response:
    return JSONResponse(
        {"error": "operator credential required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="acp-console"'},
    )


def build_page() -> Any:
    """The console itself: one file, no build step, no framework.

    Unauthenticated on purpose: it holds no data, and an address bar cannot send
    the header. The stream checks the credential.
    """

    async def page(_request: Request) -> Response:
        return HTMLResponse(PAGE)

    return page


def build_stream(hub: TraceHub, credential: str) -> Any:
    """The event stream, one line per thing that happened."""

    async def stream(request: Request) -> Response:
        if not _authorized(request, credential):
            return _unauthorized()

        async def body() -> AsyncIterator[str]:
            # `with`, so a vanished browser is unsubscribed when the generator closes.
            with hub.subscribe() as subscription:
                yield ": connected\n\n"
                reported = 0
                while True:
                    # Not `async for`: an idle stream must still send keepalives.
                    event = None
                    with anyio.move_on_after(KEEPALIVE_SECONDS):
                        try:
                            event = await subscription.__anext__()
                        except StopAsyncIteration:
                            return
                    yield ": keepalive\n\n" if event is None else event.as_sse()

                    # Report drops while streaming; the loop has no end.
                    if subscription.dropped > reported:
                        missed = subscription.dropped - reported
                        reported = subscription.dropped
                        yield f": {missed} events dropped, this watcher is behind\n\n"

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                # Stops Nginx-style proxies from buffering the stream.
                "X-Accel-Buffering": "no",
            },
        )

    return stream


def console_routes(hub: TraceHub | None, credential: str) -> Sequence[Route]:
    """The console's routes, or none at all.

    Without a hub or a credential the routes are absent, not closed, so nothing
    reveals what this deployment runs.
    """
    if hub is None or not credential:
        return ()
    return (
        Route(CONSOLE_PATH, build_page(), methods=["GET"]),
        Route(STREAM_PATH, build_stream(hub, credential), methods=["GET"]),
    )
