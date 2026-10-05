"""Shared Redis plumbing for the approval and budget stores (ADR 0066, ADR 0067).

`check_redis_url` rejects a non-Redis URL when settings load, so the error names
the setting. `client_for` builds a client with timeouts and a bounded pool, and
`unavailable` turns library errors into one fail-closed refusal (ADR 0070).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final

from redis.asyncio import Redis
from redis.exceptions import RedisError

from acp.exceptions import StateStoreUnavailableError

logger = logging.getLogger(__name__)

REDIS_SCHEMES: Final = ("redis://", "rediss://", "unix://")

CONNECT_TIMEOUT_SECONDS: Final = 2.0
"""TCP connect timeout, for startup pings and reconnects."""
COMMAND_TIMEOUT_SECONDS: Final = 1.0
"""Per-command timeout; commands here take microseconds, so a second means a hung server."""
MAX_CONNECTIONS: Final = 1024
"""Pool ceiling; above it the library raises rather than queues, so size it to concurrency."""
HEALTH_CHECK_INTERVAL_SECONDS: Final = 30.0
"""Idle age after which a connection is pinged before reuse, catching server restarts."""


def client_for(url: str) -> Redis:
    """A client with the timeouts and pool every store here must have."""
    return Redis.from_url(
        url,
        socket_connect_timeout=CONNECT_TIMEOUT_SECONDS,
        socket_timeout=COMMAND_TIMEOUT_SECONDS,
        max_connections=MAX_CONNECTIONS,
        health_check_interval=HEALTH_CHECK_INTERVAL_SECONDS,
    )


@asynccontextmanager
async def unavailable(what: str) -> AsyncIterator[None]:
    """Turn `RedisError`/`OSError` into `StateStoreUnavailableError`; other errors propagate."""
    try:
        yield
    except (RedisError, OSError) as exc:
        logger.exception(
            "state_store.unavailable",
            extra={"store": what, "error": type(exc).__name__, "consequence": "call refused"},
        )
        raise StateStoreUnavailableError("the request could not be checked; retry") from exc


def check_redis_url(setting: str, value: str) -> str:
    """``value`` unchanged if it is empty or a Redis URL; ``ValueError`` otherwise."""
    if value and not value.startswith(REDIS_SCHEMES):
        schemes = ", ".join(REDIS_SCHEMES)
        msg = f"{setting} must start with one of {schemes}"
        raise ValueError(msg)
    return value
