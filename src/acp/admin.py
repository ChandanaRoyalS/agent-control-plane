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

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from acp import __version__
from acp.observability import metrics

METRICS_PATH = "/metrics"
HEALTH_PATH = "/healthz"


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


def build_admin_app() -> Starlette:
    """The admin ASGI app. Small on purpose — it must not be able to fail."""
    return Starlette(
        routes=[
            Route(METRICS_PATH, _metrics, methods=["GET"]),
            Route(HEALTH_PATH, _healthz, methods=["GET"]),
        ]
    )
