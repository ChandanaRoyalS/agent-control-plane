"""ASGI middleware that turns a bearer token into a bound principal.

Raw ASGI, because ``BaseHTTPMiddleware`` runs the app in another task and the bound
context would not reach the handler (see ``acp.observability.middleware``). Failures are an
HTTP 401 with ``WWW-Authenticate`` (RFC 6750 §3) carrying only ``invalid_token``; the cause
goes to the log. Only the RFC 9728 metadata path is public (see ``acp.identity.resource``).
With no validator every request runs as ``anonymous``, which startup and every log line say.
"""

from __future__ import annotations

import json
import logging
from collections.abc import MutableMapping, Sequence
from typing import Any

from acp.exceptions import ACPError, AuthenticationError
from acp.identity.principal import bind_principal, bind_subject_token
from acp.identity.resource import ProtectedResource
from acp.identity.validator import TokenValidator
from acp.observability import context

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]

AUTHORIZATION_HEADER = b"authorization"
BEARER = "bearer"

MAX_TOKEN_LENGTH = 8192
"""Longest bearer token examined; bounds decode work on an oversized header."""

ANONYMOUS = "anonymous"
"""Log value for a request with no identity; a literal so it is searchable."""


class AuthenticationMiddleware:
    """Resolves the caller's principal, or refuses the request."""

    def __init__(
        self,
        app: Any,
        validator: TokenValidator | None,
        resource: ProtectedResource | None = None,
    ) -> None:
        self._app = app
        self._validator = validator
        self._resource = resource
        # Derived from the resource, never configured: no `public_paths` list to grow.
        self._public: frozenset[str] = (
            frozenset({resource.metadata_path}) if resource is not None else frozenset()
        )

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # Exact equality, never a prefix test: encodings, dot segments and trailing
        # slashes fail closed into normal authentication.
        if scope.get("path", "") in self._public:
            bind_principal(None)
            bind_subject_token(None)
            context.bind(principal=ANONYMOUS)
            await self._app(scope, receive, send)
            return

        if self._validator is None:
            # Bound explicitly so None in `current_principal()` is a decision.
            bind_principal(None)
            bind_subject_token(None)
            context.bind(principal=ANONYMOUS)
            await self._app(scope, receive, send)
            return

        token = _bearer_token(scope)
        if token is None:
            # RFC 6750 §3: no credentials means a challenge without an `error` code.
            await self._challenge(send, error=None)
            return

        try:
            principal = await self._validator.validate(token)
        except AuthenticationError:
            await self._challenge(send, error="invalid_token")
            return
        except ACPError:
            # IdP failure is 503, not 401: a 401 would send agents to re-authenticate
            # against a broken IdP.
            logger.exception("auth.provider_unavailable")
            await _unavailable(send)
            return

        bind_principal(principal)
        # Kept off the principal; only `acp.identity.exchange` reads it.
        bind_subject_token(token)
        context.bind(**principal.as_log_fields())
        await self._app(scope, receive, send)

    async def _challenge(self, send: Any, *, error: str | None) -> None:
        """Answer 401 with a ``WWW-Authenticate`` challenge.

        Adds ``resource_metadata`` (RFC 9728 §5.1) only when a document exists to point at.
        """
        parameters = [] if error is None else [f'error="{error}"']
        if self._resource is not None:
            parameters.append(f'resource_metadata="{self._resource.metadata_url}"')
        challenge = "Bearer" + (" " + ", ".join(parameters) if parameters else "")
        await _respond(
            send,
            status=401,
            body={"error": error or "unauthorized"},
            headers=[(b"www-authenticate", challenge.encode("ascii"))],
        )


def _bearer_token(scope: Scope) -> str | None:
    """Return the bearer token, or ``None`` if absent, oversized or malformed.

    The scheme is matched case-insensitively (RFC 7235).
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
