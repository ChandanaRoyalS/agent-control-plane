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
from acp.health import DEFAULT_INTERVAL, HealthMonitor
from acp.upstream import Upstream, UpstreamConfig, connect_upstream

logger = logging.getLogger(__name__)


@asynccontextmanager
async def gateway_from_configs(
    upstreams: Sequence[UpstreamConfig],
    *,
    allowed_hosts: Sequence[str] = (),
    allowed_origins: Sequence[str] = (),
    probe_health: bool = False,
    probe_interval: float = DEFAULT_INTERVAL,
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

        monitor = HealthMonitor(clients, interval=probe_interval) if probe_health else None
        app = build_app(
            UpstreamRegistry(clients, monitor),
            allowed_hosts=allowed_hosts or ("127.0.0.1", "localhost"),
            allowed_origins=allowed_origins,
        )
        # Attached rather than yielded, so the signature every existing caller
        # and test depends on is unchanged. The probe loop itself is started by
        # whoever owns a task group — deliberately not here: starting a
        # long-lived task inside an async generator puts its cancel scope in a
        # different task from the one that exits the generator, which is the
        # classic way to get a cancellation that fires in the wrong place.
        app.state.health = monitor
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
        probe_health=settings.health_probing_enabled,
        probe_interval=settings.health_probe_interval,
        # Expanded to include `host:port`, because that is what a client
        # actually sends in the Host header on a non-default port.
        allowed_hosts=allowed_hosts_for(settings.allowed_hosts, settings.port),
        allowed_origins=settings.allowed_origins,
    ) as app:
        yield app
