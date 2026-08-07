"""The admin surface: metrics now, health checks in task 18.

**On a separate port from the gateway itself.** That is the whole reason this is
its own module rather than two more routes on the MCP app.

A scrape endpoint is not neutral. It publishes every upstream's name, every
tool's name, the shape of the traffic and which dependencies are currently
failing — which is a reconnaissance report for anyone deciding what to attack.
For a component whose purpose is to sit between agents and the things they can
do, putting that on the same listener as the thing being protected is the wrong
default, and "we'll firewall it later" is how it ends up public.

So: a second listener, bound to loopback by default, that a sidecar or a scrape
job on the same host can reach and nothing else can. Making it *available*
elsewhere becomes a deliberate act of configuration, which is the direction a
security control should fail in.

The cost is a second server in the process. It is about ten lines in
``runtime``, and task 18's health endpoints land here for free.
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from acp import __version__
from acp.health import HealthMonitor
from acp.observability import metrics
from acp.schema import DriftDetector

METRICS_PATH = "/metrics"
HEALTH_PATH = "/healthz"
READY_PATH = "/readyz"
SCHEMAS_PATH = "/schemas"


async def _metrics(_request: Request) -> Response:
    """Prometheus exposition.

    Deliberately not wrapped in the request-context middleware. A scrape every
    fifteen seconds forever would otherwise produce a log line every fifteen
    seconds forever, burying the traffic anyone actually cares about under
    monitoring of the monitoring.
    """
    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)


async def _healthz(_request: Request) -> Response:
    """Liveness only: this process is up and serving.

    Deliberately *not* a readiness check and deliberately not a report on the
    upstreams. A liveness probe that fails when a dependency is unhealthy gets
    the container restarted for someone else's outage — which turns one broken
    upstream into a crash loop. Task 18 adds a real readiness endpoint that
    reports upstream health without conflating the two.
    """
    return PlainTextResponse(f"ok {__version__}\n")


def build_readyz(health: HealthMonitor | None) -> Any:
    """Readiness: can this gateway currently serve a useful request?

    503 when upstreams are configured and *none* of them can serve, because at
    that point every ``tools/list`` raises anyway (the total-failure policy) and
    reporting ready would be a lie a load balancer believes.

    Two consequences worth stating rather than discovering.

    Every replica shares the same upstreams, so a total upstream outage fails
    readiness on all of them at once. That is accepted deliberately: the
    alternative is a fleet that reports ready while erroring every request,
    which is worse for anyone reading a dashboard at the time.

    A gateway with **no** upstreams configured is ready. Nothing is wrong with
    it; it simply has nothing attached yet, which is a legitimate way to bring
    one up — the same distinction ``Catalogue.is_total_failure`` draws.
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
    """Current distance from the committed schema baseline (task 20).

    Always 200, including when there is drift. Drift is not an outage and must
    not read as one: a catalogue that changed is a thing for a human to look at,
    not a reason for a load balancer to take a healthy gateway out of rotation.
    That is also why it is a route of its own rather than a field on ``/readyz``
    — the two are read by different consumers for different purposes, and
    merging them would eventually have somebody wiring drift into a probe.

    Reports the *whole* outstanding difference every time, not only what is new.
    The log line is the edge-triggered alert; this is the level-triggered view
    you check when you are already looking.
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
    health: HealthMonitor | None = None, drift: DriftDetector | None = None
) -> Starlette:
    """The admin ASGI app. Small on purpose — it must not be able to fail."""
    return Starlette(
        routes=[
            Route(METRICS_PATH, _metrics, methods=["GET"]),
            Route(HEALTH_PATH, _healthz, methods=["GET"]),
            Route(READY_PATH, build_readyz(health), methods=["GET"]),
            Route(SCHEMAS_PATH, build_schemas(drift), methods=["GET"]),
        ]
    )
