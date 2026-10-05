"""ASGI middleware that opens a request scope and logs the outcome.

Raw ASGI rather than Starlette's ``BaseHTTPMiddleware``, which runs the handler in another
task and breaks streaming responses and context propagation.
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
"""Longest inbound request ID accepted; longer (attacker-controlled) IDs are replaced."""

REQUEST_ID_HEADER = b"x-request-id"
"""Honoured on the way in and echoed on the response."""


class RequestContextMiddleware:
    """Binds a request ID for the life of each HTTP request, and times it."""

    def __init__(self, app: Any, *, header: bytes = REQUEST_ID_HEADER) -> None:
        self._app = app
        self._header = header

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            # Lifespan and websocket scopes pass through untouched.
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
    # Annotated so the scope's `Any` does not leak past strict type checking.
    headers: Sequence[tuple[bytes, bytes]] = scope.get("headers") or []
    for key, value in headers:
        if key.lower() == name:
            decoded = value.decode("latin-1").strip()
            # Bounded printable ASCII only: no log injection via the caller's ID.
            if (
                decoded.isascii()
                and decoded.isprintable()
                and 0 < len(decoded) <= MAX_INBOUND_ID_LENGTH
            ):
                return decoded
    return None


def _elapsed(started: float) -> float:
    return float(round((time.perf_counter() - started) * 1000, 2))
