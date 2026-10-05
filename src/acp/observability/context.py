"""Request-scoped log context (request ID and bound fields) carried in a ``ContextVar``.

Child tasks inherit a copy at creation, so their own bindings never leak into siblings. The
mapping is immutable and always replaced, since a mutable dict would be shared by reference.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any

_EMPTY: Mapping[str, Any] = MappingProxyType({})

_context: ContextVar[Mapping[str, Any]] = ContextVar("acp_log_context", default=_EMPTY)

REQUEST_ID = "request_id"
"""The one field every log line in a request is expected to carry."""


def new_request_id() -> str:
    """A fresh UUID4 hex correlation ID, unique across replicas and restarts."""
    return uuid.uuid4().hex


def current() -> Mapping[str, Any]:
    """Everything bound in the current context. Never ``None``, possibly empty."""
    return _context.get()


def request_id() -> str | None:
    """The current request's ID, or ``None`` outside a request."""
    value = _context.get().get(REQUEST_ID)
    return value if isinstance(value, str) else None


def bind(**fields: Any) -> None:
    """Add fields to the current context for the rest of this task (e.g. the principal)."""
    _context.set(MappingProxyType({**_context.get(), **fields}))


@contextmanager
def context(**fields: Any) -> Iterator[Mapping[str, Any]]:
    """Bind fields for a block, then restore the previous context via its token (nests safely)."""
    token = _context.set(MappingProxyType({**_context.get(), **fields}))
    try:
        yield _context.get()
    finally:
        _context.reset(token)


@contextmanager
def request(request_id: str | None = None, **fields: Any) -> Iterator[str]:
    """Open a request scope, reusing an inbound ID (e.g. from a proxy) or generating one."""
    resolved = request_id or new_request_id()
    with context(**{REQUEST_ID: resolved, **fields}):
        yield resolved


def clear() -> None:
    """Drop all bound context. For tests and long-lived worker loops."""
    _context.set(_EMPTY)
