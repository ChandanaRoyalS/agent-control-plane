"""The routes a watcher talks to — task 63.

**On the admin listener, never the gateway's.** The same argument as the
operator channel (ADR 0049): this stream carries *every principal's* activity,
so an agent that could open it would read what every other caller is doing. An
agent cannot address the thing that watches it, for the same reason it cannot
address the thing that approves its calls.

**And behind the operator credential**, because "loopback only" is a default
somebody changes and a trace of every call is a better prize than most.

**Why `fetch`, and not `EventSource`.**

`EventSource` is the browser API built for this, and it **cannot set request
headers**. The usual workaround is a credential in the query string, which puts
a secret into browser history, into the referrer of anything the page loads, and
into every access log between here and the tab.

So the page uses `fetch()` with an `Authorization` header and reads the response
body as a stream. That is more code in the page and the correct amount of code
in the log. The wire format stays Server-Sent Events — the plan asks for SSE and
the framing is genuinely good — it is only the client that is hand-rolled.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Sequence
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from acp.console.hub import TraceHub
from acp.console.page import PAGE

CONSOLE_PATH = "/console"
STREAM_PATH = "/console/stream"

KEEPALIVE_SECONDS = 15.0
"""How often to send an SSE comment when nothing is happening.

Not decoration: an idle connection through a proxy or a laptop's NAT is closed
somewhere between here and the browser, usually silently, and the console then
shows nothing for a reason that looks exactly like "no traffic". A colon-prefixed
line is a comment in the SSE grammar — it keeps the connection warm and is
ignored by the parser.
"""


def _authorized(request: Request, credential: str) -> bool:
    """Whether this request carries the operator credential.

    `compare_digest` rather than `==`, and for the reason the operator channel
    gives: a short-circuiting comparison against a secret leaks its prefix one
    request at a time, and this is a listener somebody will eventually expose
    beyond loopback whatever the default says.
    """
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return secrets.compare_digest(presented, credential)


def _unauthorized() -> Response:
    return JSONResponse(
        {"error": "operator credential required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="acp-console"'},
    )


def build_page() -> Any:
    """The console itself: one file, no build step, no framework.

    Served **unauthenticated on purpose**, and that is a decision rather than an
    oversight: it contains no data. It is markup and a fetch loop, and the stream
    it talks to is the thing that checks a credential. Gating the page as well
    would mean a browser cannot open it at all — `fetch` can carry a header and
    an address bar cannot — so the only effect would be to make the console
    unreachable while protecting nothing.
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
            # `with`, so a browser that disappears mid-stream cannot leave a
            # subscriber attached to the hub receiving events forever. The
            # generator is closed when the response is, and `__exit__`
            # unsubscribes — which is the only thing standing between a demo
            # and a slow leak of dead watchers.
            with hub.subscribe() as subscription:
                yield ": connected\n\n"
                reported = 0
                while True:
                    # Not `async for`: a quiet stream has to emit something
                    # periodically or an idle connection is dropped in the
                    # middle somewhere, and the console then shows nothing for
                    # a reason indistinguishable from "no traffic".
                    event = None
                    with anyio.move_on_after(KEEPALIVE_SECONDS):
                        try:
                            event = await subscription.__anext__()
                        except StopAsyncIteration:
                            return
                    yield ": keepalive\n\n" if event is None else event.as_sse()

                    # Reported *while streaming*, not at the end — there is no
                    # end, and a first version of this put the notice after the
                    # loop where mypy's unreachable check found it. A trace
                    # console that quietly omits events is worse than no
                    # console, because it is read as complete.
                    if subscription.dropped > reported:
                        missed = subscription.dropped - reported
                        reported = subscription.dropped
                        yield f": {missed} events dropped, this watcher is behind\n\n"

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                # Nginx and friends buffer proxied responses by default, which
                # turns a live stream into a batch delivered when the buffer
                # fills. There is no proxy in the compose stack; this is here
                # because the first thing anybody does with a demo is put one
                # in front of it.
                "X-Accel-Buffering": "no",
            },
        )

    return stream


def console_routes(hub: TraceHub | None, credential: str) -> Sequence[Route]:
    """The console's routes, or none at all.

    Two ways to get nothing, and they are the same answer to different
    questions: nothing to watch (no hub), or nobody entitled to watch it (no
    credential). Either way the routes are **absent rather than present and
    closed**, following the operator channel: a route that exists and always
    refuses still tells an unauthenticated caller what this deployment runs.
    """
    if hub is None or not credential:
        return ()
    return (
        Route(CONSOLE_PATH, build_page(), methods=["GET"]),
        Route(STREAM_PATH, build_stream(hub, credential), methods=["GET"]),
    )
