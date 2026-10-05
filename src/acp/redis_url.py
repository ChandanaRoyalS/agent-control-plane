"""What every Redis this gateway talks to has in common.

Two settings point at a Redis — the approval store (ADR 0066) and the budget
store (ADR 0067) — and both must refuse a URL that is not one at load, where
the message can name the setting, rather than at the first connection, where
the failure would be a gateway holding calls in nothing. The check is the same
and lives once.

So does the client. A Redis client built with no timeouts waits forever on a
hung server, and a gateway with one such wait on its request path has every
budgeted or held call behind it; a client with the library's default pool
refuses the two-hundred-and-first concurrent command with an error rather than
a queue. `client_for` sets both (ADR 0070), and the request path turns what
the library raises into one typed, fail-closed refusal (`unavailable`).
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
"""How long to wait for a TCP connection. Startup pings and reconnects."""
COMMAND_TIMEOUT_SECONDS: Final = 1.0
"""How long one command may take. A budget charge or an approval read is a
few microseconds of server work; a second is a hung server, not a slow one."""
MAX_CONNECTIONS: Final = 1024
"""Pool ceiling. Above it the library raises rather than queues, so this is
sized to the concurrency a single gateway is expected to carry, with headroom;
a deployment carrying more should raise it and the worker count together."""
HEALTH_CHECK_INTERVAL_SECONDS: Final = 30.0
"""How stale an idle connection may be before it is pinged before reuse, so a
server restart is noticed on the next command rather than reported as a
broken pipe mid-call."""


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
    """Turn the library's failures into the gateway's one refusal.

    `RedisError` covers connection, timeout and pool exhaustion; `OSError` is
    what a refused socket raises underneath it. Anything else is a bug and
    propagates as one.
    """
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
