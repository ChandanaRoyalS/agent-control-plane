"""Integration tests for the admin listener.

Driven through the real ASGI app, because the properties worth asserting are
about what it serves and — more importantly — what it does *not*. This app is
the one surface that has no authentication in front of it, so what it exposes is
a security decision rather than a convenience.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.admin import HEALTH_PATH, METRICS_PATH, READY_PATH, build_admin_app
from acp.health import HealthRecord, UpstreamHealth

pytestmark = pytest.mark.integration


def get(path: str) -> httpx.Response:
    async def _run() -> httpx.Response:
        transport = httpx.ASGITransport(app=build_admin_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.get(path)

    response: httpx.Response = anyio.run(_run)
    return response


def test_metrics_are_served() -> None:
    response = get(METRICS_PATH)

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]


def test_metrics_answer_even_with_nothing_recorded() -> None:
    """A scrape that 500s reads as "the gateway is broken" when it means "no
    traffic yet" — and a monitoring system that cries wolf on a fresh deploy
    gets its alerts muted."""
    assert get(METRICS_PATH).status_code == 200


def test_liveness_reports_the_version() -> None:
    response = get(HEALTH_PATH)

    assert response.status_code == 200
    assert response.text.startswith("ok ")


def test_liveness_does_not_depend_on_the_upstreams() -> None:
    """Deliberately not a readiness check.

    A liveness probe that fails because a dependency is unhealthy gets the
    container restarted for somebody else's outage, turning one broken upstream
    into a crash loop across every replica. Task 18 adds a readiness endpoint
    that reports upstream health without conflating the two.
    """
    assert get(HEALTH_PATH).status_code == 200


def test_the_admin_app_serves_nothing_else() -> None:
    """Small on purpose. Every route here is one more thing reachable without
    authentication."""
    for path in ("/", "/mcp", "/config", "/debug"):
        assert get(path).status_code == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_the_admin_surface_is_read_only(method: str) -> None:
    """Nothing here changes anything, and the router should enforce that rather
    than relying on the handlers not to."""

    async def _run() -> httpx.Response:
        transport = httpx.ASGITransport(app=build_admin_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(method, METRICS_PATH)

    response: httpx.Response = anyio.run(_run)

    assert response.status_code == 405


def test_the_admin_app_is_separate_from_the_gateway_app() -> None:
    """The design claim this module rests on.

    Metrics publish every upstream name, every tool name and which dependencies
    are failing. On the gateway's own listener that is a reconnaissance report
    served to whoever can reach the thing being protected.
    """
    app: Any = build_admin_app()
    paths = {route.path for route in app.routes}

    assert "/mcp" not in paths
    assert paths == {METRICS_PATH, HEALTH_PATH, READY_PATH}


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------


class FakeMonitor:
    """Stands in for a HealthMonitor without needing upstreams to probe."""

    def __init__(self, records: dict[str, Any], serving_nothing: bool) -> None:
        self._records = records
        self.is_serving_nothing = serving_nothing

    def snapshot(self) -> dict[str, Any]:
        return self._records


def ready(monitor: Any) -> httpx.Response:
    async def _run() -> httpx.Response:
        transport = httpx.ASGITransport(app=build_admin_app(monitor))
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.get(READY_PATH)

    response: httpx.Response = anyio.run(_run)
    return response


def test_readiness_without_probing_reports_ready_and_says_so() -> None:
    """A gateway with probing disabled is not unready — it is unmonitored, and
    the payload distinguishes the two rather than implying health it has not
    checked."""
    body = ready(None).json()

    assert body == {"ready": True, "probing": False, "upstreams": []}


def test_a_healthy_upstream_makes_the_gateway_ready() -> None:
    record = HealthRecord("mock-a", UpstreamHealth.HEALTHY, checked_at=1.0, tool_count=3)
    response = ready(FakeMonitor({"mock-a": record}, serving_nothing=False))

    assert response.status_code == 200
    assert response.json()["upstreams"][0]["tools"] == 3


def test_readiness_fails_only_when_nothing_can_be_served() -> None:
    """503 because every `tools/list` would raise anyway under the total-failure
    policy. Reporting ready there is a lie a load balancer believes."""
    record = HealthRecord("mock-a", UpstreamHealth.UNHEALTHY, error="UpstreamUnavailableError")
    response = ready(FakeMonitor({"mock-a": record}, serving_nothing=True))

    assert response.status_code == 503
    assert response.json()["ready"] is False


def test_partial_service_is_still_ready() -> None:
    """The whole partial-failure policy rests on one upstream dying not being
    treated as an outage."""
    records = {
        "mock-a": HealthRecord("mock-a", UpstreamHealth.UNHEALTHY, error="UpstreamTimeoutError"),
        "mock-b": HealthRecord("mock-b", UpstreamHealth.HEALTHY, tool_count=3),
    }
    response = ready(FakeMonitor(records, serving_nothing=False))

    assert response.status_code == 200


def test_readiness_reports_error_types_never_messages() -> None:
    """This endpoint has no authentication in front of it. An exception message
    quotes hosts, arguments and upstream responses; a class name does not."""
    record = HealthRecord("mock-a", UpstreamHealth.UNHEALTHY, error="UpstreamUnavailableError")
    body = ready(FakeMonitor({"mock-a": record}, serving_nothing=True)).text

    assert "UpstreamUnavailableError" in body
    assert "10." not in body
    assert "http" not in body
