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
from pathlib import Path

from starlette.applications import Starlette

from acp.config import GatewaySettings, allowed_hosts_for, load_upstreams
from acp.exceptions import ConfigurationError
from acp.gateway import UpstreamRegistry, build_app
from acp.health import DEFAULT_INTERVAL, HealthMonitor
from acp.identity import JwksCache, TokenPolicy, TokenValidator
from acp.schema import DEFAULT_BASELINE_PATH, DriftDetector, SchemaSnapshot
from acp.upstream import Upstream, UpstreamConfig, connect_upstream

logger = logging.getLogger(__name__)


def build_drift_detector(baseline_file: Path, known: Sequence[str]) -> DriftDetector:
    """Load the committed baseline, tolerating its absence and its corruption.

    The only place in this project where a bad file on disk does *not* stop the
    process. Configuration failures are fatal by design — a gateway that starts
    with a broken policy has already failed open. A schema baseline is the other
    kind of thing: it is a monitor, and a monitor that can prevent the gateway
    from serving is a bigger risk than the one it exists to reduce. So a
    corrupt baseline is logged at ERROR and treated as no baseline, which
    reports every upstream as unbaselined — noisy, obvious, and not an outage.
    """
    try:
        baseline = SchemaSnapshot.load(baseline_file)
    except ConfigurationError as exc:
        logger.error(  # noqa: TRY400 — the traceback adds nothing; the message is the point
            "schema.baseline_unreadable",
            extra={"path": str(baseline_file), "error": exc.message},
        )
        baseline = None

    if baseline is None:
        logger.warning(
            "schema.baseline_missing",
            extra={"path": str(baseline_file), "hint": "run `acp schemas capture`"},
        )
    return DriftDetector(baseline, known=known)


@asynccontextmanager
async def gateway_from_configs(
    upstreams: Sequence[UpstreamConfig],
    *,
    allowed_hosts: Sequence[str] = (),
    allowed_origins: Sequence[str] = (),
    probe_health: bool = False,
    probe_interval: float = DEFAULT_INTERVAL,
    detect_drift: bool = False,
    baseline_file: Path | None = None,
    validator: TokenValidator | None = None,
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

        # Drift detection rides on the health prober's fetch (see
        # `acp.schema.detector`), so it needs one to ride on. Asking for it
        # without probing is a configuration that cannot do what it says, and
        # saying so beats silently detecting nothing.
        detector: DriftDetector | None = None
        if detect_drift and probe_health:
            detector = build_drift_detector(
                baseline_file or DEFAULT_BASELINE_PATH,
                [c.config.name for c in clients],
            )
        elif detect_drift:
            logger.warning("schema.drift_detection_inert", extra={"reason": "probing disabled"})

        monitor = (
            HealthMonitor(
                clients,
                interval=probe_interval,
                on_catalogue=detector.observe if detector else None,
            )
            if probe_health
            else None
        )
        if validator is None:
            # Said once, at startup, at WARNING. The other half of making this
            # impossible to miss is that every request then logs
            # `principal: anonymous` — see `acp.identity.asgi`.
            logger.warning(
                "auth.disabled",
                extra={"reason": "no identity provider configured", "principal": "anonymous"},
            )

        app = build_app(
            UpstreamRegistry(clients, monitor),
            allowed_hosts=allowed_hosts or ("127.0.0.1", "localhost"),
            allowed_origins=allowed_origins,
            validator=validator,
        )
        # Attached rather than yielded, so the signature every existing caller
        # and test depends on is unchanged. The probe loop itself is started by
        # whoever owns a task group — deliberately not here: starting a
        # long-lived task inside an async generator puts its cancel scope in a
        # different task from the one that exits the generator, which is the
        # classic way to get a cancellation that fires in the wrong place.
        app.state.health = monitor
        app.state.schema_drift = detector
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


def build_token_validator(settings: GatewaySettings) -> TokenValidator | None:
    """Assemble token validation, or ``None`` when no provider is configured.

    Note what is *not* here: a flag. Authentication is on when an identity
    provider is configured and off when one is not — see ``acp.config`` for why
    a boolean is the wrong control for this. A partially configured provider is
    already a startup failure by then, so reaching this function with some
    settings and not others is impossible.

    ``TokenPolicy`` refuses a symmetric algorithm in its constructor, so a
    configuration that would accept forged tokens fails here, before a port is
    bound, rather than on the first request that exploits it.
    """
    if not settings.authentication_configured:
        return None

    policy = TokenPolicy(
        issuer=settings.auth_issuer,
        audience=settings.auth_audience,
        algorithms=tuple(settings.auth_algorithms),
        leeway=settings.auth_leeway,
    )
    keys = JwksCache(
        settings.auth_jwks_url,
        ttl=settings.auth_jwks_cache_ttl,
        min_refresh_interval=settings.auth_jwks_min_refresh_interval,
    )
    logger.info(
        "auth.enabled",
        extra={
            "issuer": settings.auth_issuer,
            "audience": settings.auth_audience,
            "jwks_url": settings.auth_jwks_url,
            "algorithms": list(settings.auth_algorithms),
        },
    )
    return TokenValidator(policy=policy, keys=keys)


@asynccontextmanager
async def gateway_from_settings(settings: GatewaySettings) -> AsyncIterator[Starlette]:
    """Build the gateway described by ``settings``.

    Upstreams are read and validated *before* any connection is opened, so a
    malformed config fails without side effects.
    """
    upstreams = load_upstreams(settings.upstreams_file)
    validator = build_token_validator(settings)
    try:
        async with gateway_from_configs(
            upstreams,
            probe_health=settings.health_probing_enabled,
            probe_interval=settings.health_probe_interval,
            detect_drift=settings.schema_drift_detection_enabled,
            baseline_file=settings.schema_baseline_file,
            # Expanded to include `host:port`, because that is what a client
            # actually sends in the Host header on a non-default port.
            allowed_hosts=allowed_hosts_for(settings.allowed_hosts, settings.port),
            allowed_origins=settings.allowed_origins,
            validator=validator,
        ) as app:
            yield app
    finally:
        # The key cache owns an HTTP connection pool, for the same reason the
        # upstream clients do and with the same consequence for leaking it.
        if validator is not None:
            await validator.keys.aclose()
