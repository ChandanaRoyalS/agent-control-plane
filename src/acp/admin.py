"""The admin app: metrics, health, readiness, approvals and console, on their own listener.

Kept off the gateway port because metrics reveal upstreams, tools and failing
dependencies to an attacker; the listener binds to loopback by default, so exposing
it elsewhere is a deliberate configuration choice.
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from acp import __version__
from acp.approvals.operator import operator_routes
from acp.approvals.store import ApprovalStore
from acp.audit import AuditLog
from acp.console.app import console_routes
from acp.console.hub import TraceHub
from acp.health import HealthMonitor
from acp.identity import TokenValidator
from acp.observability import metrics
from acp.schema import DriftDetector

METRICS_PATH = "/metrics"
HEALTH_PATH = "/healthz"
READY_PATH = "/readyz"
SCHEMAS_PATH = "/schemas"


async def _metrics(_request: Request) -> Response:
    """Prometheus exposition; skips request-context middleware so scrapes are not logged."""
    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)


async def _healthz(_request: Request) -> Response:
    """Liveness only; ignores upstreams so an upstream outage cannot cause a restart loop."""
    return PlainTextResponse(f"ok {__version__}\n")


def build_readyz(health: HealthMonitor | None) -> Any:
    """Readiness route: 503 when upstreams are configured and none can serve.

    A total upstream outage therefore fails readiness on every replica at once, by
    design. With no upstreams configured the gateway is ready, as in
    ``Catalogue.is_total_failure``.
    """

    async def readyz(_request: Request) -> Response:
        if health is None:
            return JSONResponse({"ready": True, "probing": False, "upstreams": []})

        records = health.snapshot()
        ready = not health.is_serving_nothing
        return JSONResponse(
            {
                "ready": ready,
                "probing": True,
                "upstreams": [records[name].as_dict() for name in sorted(records)],
            },
            status_code=200 if ready else 503,
        )

    return readyz


def build_schemas(detector: DriftDetector | None) -> Any:
    """Schema-drift route: the whole outstanding difference from the committed baseline.

    Always 200, and separate from ``/readyz``, so drift never takes a gateway out of
    rotation.
    """

    async def schemas(_request: Request) -> Response:
        if detector is None:
            return JSONResponse({"detecting": False, "baseline": False, "drift": False})
        report = detector.report()
        return JSONResponse(
            {"detecting": True, "baseline": detector.has_baseline, **report.as_dict()}
        )

    return schemas


def build_admin_app(
    health: HealthMonitor | None = None,
    drift: DriftDetector | None = None,
    approvals: ApprovalStore | None = None,
    operator_credential: str = "",
    audit: AuditLog | None = None,
    *,
    console: TraceHub | None = None,
    operator_validator: TokenValidator | None = None,
) -> Starlette:
    """The admin ASGI app; kept small so it cannot fail.

    Approvals live here, not on the gateway port, so an agent cannot reach the channel
    that approves its own calls (see `acp.approvals.operator`). They are the only
    authenticated routes, and are absent when no credential is configured.
    `console` is keyword-only so the `X | None` arguments cannot be transposed.
    """
    return Starlette(
        routes=[
            Route(METRICS_PATH, _metrics, methods=["GET"]),
            Route(HEALTH_PATH, _healthz, methods=["GET"]),
            Route(READY_PATH, build_readyz(health), methods=["GET"]),
            Route(SCHEMAS_PATH, build_schemas(drift), methods=["GET"]),
            *operator_routes(approvals, operator_credential, audit, operator_validator),
            # Streams every principal's activity: admin port, operator credential.
            *console_routes(console, operator_credential),
        ]
    )
