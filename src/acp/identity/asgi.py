"""The ASGI middleware that turns a bearer token into a principal.

Raw ASGI rather than Starlette's ``BaseHTTPMiddleware``, for the reasons already
argued in ``acp.observability.middleware`` — the base class runs the downstream
app in a *different task*, and this middleware's entire job is to bind something
into the context that the downstream handler must be able to read.

**401, not a JSON-RPC error.** Authentication happens before anything parses a
body, and OAuth's answer to "you are not who you say" is an HTTP 401 with a
``WWW-Authenticate`` header (RFC 6750 §3). Returning a JSON-RPC error would also
mean returning 200, which tells every proxy and client in the path that the
request succeeded.

**The reason never crosses the wire.** ``error="invalid_token"`` and nothing
else. The specific cause is already in the log, where the operator can read it
and an attacker cannot.

**Unauthenticated mode is a real mode, and it is loud.** With no identity
provider configured, this middleware binds ``None`` and lets the request
through. That is how every task before this one behaved, and pretending
otherwise would mean the gateway could not run at all until Phase 2 finishes.
What it must never be is *quiet*: startup warns, and every log line for every
request carries ``principal: anonymous``, so no one can read a log and fail to
notice.
"""

from __future__ import annotations

import json
import logging
from collections.abc import MutableMapping, Sequence
from typing import Any

from acp.exceptions import ACPError, AuthenticationError
from acp.identity.principal import bind_principal
from acp.identity.validator import TokenValidator
from acp.observability import context

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]

AUTHORIZATION_HEADER = b"authorization"
BEARER = "bearer"

MAX_TOKEN_LENGTH = 8192
"""Longest bearer token this will even look at.

A JWT with a large key set reference runs to a couple of kilobytes; eight is
generous. Unbounded, the header is a way to make the gateway allocate and
base64-decode megabytes before deciding the caller is anonymous.
"""

ANONYMOUS = "anonymous"
"""What the log says when a request carried no identity. A literal, so that
searching for it finds every unauthenticated request in the estate."""


class AuthenticationMiddleware:
    """Resolves the caller's principal, or refuses the request."""

    def __init__(self, app: Any, validator: TokenValidator | None) -> None:
        self._app = app
        self._validator = validator

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        if self._validator is None:
            # No identity provider configured. Bound explicitly rather than left
            # unset, so `current_principal()` returns None because somebody
            # decided it should, not because nothing ran.
            bind_principal(None)
            context.bind(principal=ANONYMOUS)
            await self._app(scope, receive, send)
            return

        token = _bearer_token(scope)
        if token is None:
            # No credentials at all. RFC 6750 §3: challenge without an `error`
            # code, because there is nothing wrong with the credentials — there
            # are none.
            await _challenge(send, error=None)
            return

        try:
            principal = await self._validator.validate(token)
        except AuthenticationError:
            await _challenge(send, error="invalid_token")
            return
        except ACPError:
            # The identity provider is unreachable or answering nonsense. This
            # is not the caller's fault and must not be reported as though their
            # token were bad — 503 says "try again", 401 says "get a new token",
            # and sending an agent to re-authenticate against a broken IdP is
            # how a dependency outage becomes a login storm.
            logger.exception("auth.provider_unavailable")
            await _unavailable(send)
            return

        bind_principal(principal)
        context.bind(**principal.as_log_fields())
        await self._app(scope, receive, send)


def _bearer_token(scope: Scope) -> str | None:
    """Extract a bearer token, or ``None`` if there isn't a usable one.

    The scheme is compared case-insensitively because RFC 7235 says it is
    case-insensitive, and real clients send ``bearer``.
    """
    headers: Sequence[tuple[bytes, bytes]] = scope.get("headers") or []
    for key, value in headers:
        if key.lower() != AUTHORIZATION_HEADER:
            continue
        if len(value) > MAX_TOKEN_LENGTH:
            return None
        try:
            decoded = value.decode("ascii")
        except UnicodeDecodeError:
            return None
        scheme, _, credentials = decoded.partition(" ")
        if scheme.lower() != BEARER:
            return None
        credentials = credentials.strip()
        return credentials or None
    return None


async def _challenge(send: Any, *, error: str | None) -> None:
    """Answer 401 with a ``WWW-Authenticate`` challenge.

    Task 24 extends this header with the ``resource_metadata`` parameter of
    RFC 9728, which is what lets a client discover *which* authorization server
    to go and get a token from rather than having it configured by hand.
    """
    challenge = "Bearer" if error is None else f'Bearer error="{error}"'
    await _respond(
        send,
        status=401,
        body={"error": error or "unauthorized"},
        headers=[(b"www-authenticate", challenge.encode("ascii"))],
    )


async def _unavailable(send: Any) -> None:
    await _respond(send, status=503, body={"error": "identity_provider_unavailable"})


async def _respond(
    send: Any,
    *,
    status: int,
    body: dict[str, str],
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
                *(headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})
