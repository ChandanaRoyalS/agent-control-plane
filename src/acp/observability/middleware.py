"""ASGI middleware that opens a request scope and logs the outcome.

Written against the raw ASGI interface rather than Starlette's
``BaseHTTPMiddleware``. That base class works by running the downstream app in a
separate task and pumping the response through a memory stream, which breaks
streaming responses and — more relevant here — puts the downstream handler in a
*different task* from the middleware. Context set by the middleware would still
be visible, since the child inherits it, but anything the handler binds would be
invisible on the way back out, and cancellation semantics get subtly wrong in
ways that only show up under load. The MCP streamable-HTTP transport is a
streaming transport; this is not a place to accept that.

Raw ASGI middleware is about thirty lines and has none of those problems.
"""

from __future__ import annotations

import logging
import time
from collections.abc import MutableMapping, Sequence
from typing import Any

from acp.observability import context

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]

MAX_INBOUND_ID_LENGTH = 128
"""Longest inbound correlation ID accepted before one is generated instead.

An ID from outside is attacker-controlled and is copied onto every log line for
the request. Unbounded, it is a way to write megabytes into a log aggregator per
request at no cost to the caller.
"""

REQUEST_ID_HEADER = b"x-request-id"
"""Honoured on the way in and echoed on the way out.

Accepting an inbound ID is what lets a caller's trace survive the hop into the
gateway. Echoing it back is what lets a client quote an ID in a bug report that
can actually be found in the logs.
"""


class RequestContextMiddleware:
    """Binds a request ID for the life of each HTTP request, and times it."""

    def __init__(self, app: Any, *, header: bytes = REQUEST_ID_HEADER) -> None:
        self._app = app
        self._header = header

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            # Lifespan and websocket scopes pass through untouched. A lifespan
            # message is not a request and has no ID to correlate.
            await self._app(scope, receive, send)
            return

        inbound = _header(scope, self._header)
        started = time.perf_counter()

        with context.request(inbound, method=scope.get("method"), path=scope.get("path")) as rid:
            status_holder: dict[str, int] = {}

            async def send_wrapper(message: Message) -> None:
                if message["type"] == "http.response.start":
                    status_holder["status"] = int(message["status"])
                    headers = list(message.get("headers") or [])
                    headers.append((self._header, rid.encode("ascii")))
                    message["headers"] = headers
                await send(message)

            try:
                await self._app(scope, receive, send_wrapper)
            except Exception:
                logger.exception(
                    "http.request.failed",
                    extra={"duration_ms": _elapsed(started)},
                )
                raise

            logger.info(
                "http.request",
                extra={
                    "status": status_holder.get("status"),
                    "duration_ms": _elapsed(started),
                },
            )


def _header(scope: Scope, name: bytes) -> str | None:
    # Annotated rather than inferred: an ASGI scope is `MutableMapping[str,
    # Any]` by definition, so everything read out of it arrives as `Any` and
    # would silently defeat strict mode from here on.
    headers: Sequence[tuple[bytes, bytes]] = scope.get("headers") or []
    for key, value in headers:
        if key.lower() == name:
            decoded = value.decode("latin-1").strip()
            # Bounded, and rejected if it is not printable ASCII. An ID from
            # outside is attacker-controlled and ends up in every log line for
            # this request; a caller must not be able to inject newlines into a
            # log stream or megabytes into a field.
            if (
                decoded.isascii()
                and decoded.isprintable()
                and 0 < len(decoded) <= MAX_INBOUND_ID_LENGTH
            ):
                return decoded
    return None


def _elapsed(started: float) -> float:
    return float(round((time.perf_counter() - started) * 1000, 2))
