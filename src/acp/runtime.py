"""Process lifecycle: building the gateway from config and taking it down cleanly.

Upstream clients own connection pools, and a pool that is never closed leaks
sockets until the process dies. So their lifetime is bound to a context manager
rather than left to garbage collection.

**On draining.** ``aclose`` closes idle connections and waits for in-flight
requests on that pool to finish. It does not stop *new* requests arriving —
that is the server's job, and uvicorn already does it: on ``SIGTERM`` it stops
accepting, lets in-flight requests complete, then returns from ``serve()``, at
which point this context manager's ``finally`` runs. The ordering matters and
is the reason the clients are managed *around* the server rather than inside
the ASGI app's own lifespan.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from starlette.applications import Starlette

from acp.config import GatewaySettings, allowed_hosts_for, load_upstreams
from acp.gateway import UpstreamRegistry, build_app
from acp.upstream import Upstream, UpstreamConfig, connect_upstream

logger = logging.getLogger(__name__)


@asynccontextmanager
async def gateway_from_configs(
    upstreams: Sequence[UpstreamConfig],
    *,
    allowed_hosts: Sequence[str] = (),
    allowed_origins: Sequence[str] = (),
) -> AsyncIterator[Starlette]:
    """Build the ASGI app, and close every upstream pool on the way out.

    Clients are created one at a time and torn down in reverse on failure, so a
    bad upstream part-way through startup does not leak the pools already
    opened before it.
    """
    clients: list[Upstream] = []
    try:
        for config in upstreams:
            clients.append(await connect_upstream(config))
        logger.info(
            "gateway.ready",
            extra={
                "upstream_count": len(clients),
                "upstreams": [c.config.name for c in clients],
            },
        )

        app = build_app(
            UpstreamRegistry(clients),
            allowed_hosts=allowed_hosts or ("127.0.0.1", "localhost"),
            allowed_origins=allowed_origins,
        )
        yield app
    finally:
        # Reverse order, and every close attempted even if one raises — a
        # failure closing one pool must not strand the others open.
        for client in reversed(clients):
            try:
                await client.aclose()
            except Exception:
                logger.exception(
                    "gateway.upstream_close_failed", extra={"upstream": client.config.name}
                )
        logger.info("gateway.stopped", extra={"upstream_count": len(clients)})


@asynccontextmanager
async def gateway_from_settings(settings: GatewaySettings) -> AsyncIterator[Starlette]:
    """Build the gateway described by ``settings``.

    Upstreams are read and validated *before* any connection is opened, so a
    malformed config fails without side effects.
    """
    upstreams = load_upstreams(settings.upstreams_file)
    async with gateway_from_configs(
        upstreams,
        # Expanded to include `host:port`, because that is what a client
        # actually sends in the Host header on a non-default port.
        allowed_hosts=allowed_hosts_for(settings.allowed_hosts, settings.port),
        allowed_origins=settings.allowed_origins,
    ) as app:
        yield app
