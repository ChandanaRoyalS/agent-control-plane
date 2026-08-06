"""Request-scoped context that follows the work rather than being passed along.

The problem this solves is specific to a gateway. One inbound `tools/call`
produces a catalogue lookup, possibly several concurrent upstream requests, a
retry or two, and a breaker decision — and when something goes wrong at three in
the morning, the only question that matters is *which request was that?* Log
lines that cannot be joined back to a single request are nearly useless once
more than one agent is connected.

The obvious fix is to thread a request ID through every function signature. That
works, and it poisons every interface in the codebase with a parameter that has
nothing to do with what the function computes — including `UpstreamClient`,
whose entire virtue is that it does one small thing.

``contextvars`` is the alternative the language provides. A value set here is
visible to everything the current task awaits, and — this is the part that makes
it correct rather than merely convenient — ``asyncio`` and ``anyio`` copy the
context when a task is *created*. So a child task started inside a task group
inherits the request ID automatically, while anything it binds of its own stays
in its own copy and cannot leak sideways into a sibling handling a different
request.

The values are stored as an immutable mapping that is always replaced, never
mutated. A ``ContextVar`` holding a mutable dict looks like it works and quietly
shares state between tasks, because the copy is of the reference.
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
    """A fresh correlation ID.

    A UUID4 hex string, not a counter. Counters restart at zero on every deploy,
    so two processes in a replica set produce colliding IDs and a search across
    aggregated logs returns two unrelated requests interleaved.
    """
    return uuid.uuid4().hex


def current() -> Mapping[str, Any]:
    """Everything bound in the current context. Never ``None``, possibly empty."""
    return _context.get()


def request_id() -> str | None:
    """The current request's ID, or ``None`` outside a request."""
    value = _context.get().get(REQUEST_ID)
    return value if isinstance(value, str) else None


def bind(**fields: Any) -> None:
    """Add fields to the current context for the rest of this task.

    Used for facts discovered part-way through — the resolved upstream, the
    principal once authenticated (task 22). Replaces the mapping rather than
    mutating it, so a sibling task that copied the context earlier is unaffected.
    """
    _context.set(MappingProxyType({**_context.get(), **fields}))


@contextmanager
def context(**fields: Any) -> Iterator[Mapping[str, Any]]:
    """Bind fields for the duration of a block, then restore exactly what was.

    Restores via the token rather than by deleting the keys it added, so nesting
    works and an inner block cannot clobber an outer one's values on the way
    out.
    """
    token = _context.set(MappingProxyType({**_context.get(), **fields}))
    try:
        yield _context.get()
    finally:
        _context.reset(token)


@contextmanager
def request(request_id: str | None = None, **fields: Any) -> Iterator[str]:
    """Open a fresh request scope, generating an ID if one was not supplied.

    Accepting an inbound ID matters more than it looks: when the gateway sits
    behind a proxy or is called by another service that already has a trace, a
    generated ID would break the chain at exactly the boundary where following
    it is most valuable.
    """
    resolved = request_id or new_request_id()
    with context(**{REQUEST_ID: resolved, **fields}):
        yield resolved


def clear() -> None:
    """Drop all bound context. For tests and long-lived worker loops."""
    _context.set(_EMPTY)
