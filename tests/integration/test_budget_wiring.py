"""Settings to budgets — and two gateways draining one bucket on the real path.

The approval wiring test exists because assembly has silently dropped new
wiring before. The same risk here, with a sharper edge: a `ACP_BUDGET_STORE_URL`
that is read and not threaded through would leave each replica with its own
in-memory bucket — the gateway would *say* shared and *be* per-process, which
is the exact bug ADR 0067 closes, now with a setting claiming otherwise.

So: the setting selects the keeper; with the keeper the in-memory budgets are
not built; two gateways built around one keeper share one bucket end to end,
through the real authenticated `tools/call` path; and an unreachable store
refuses to start.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import Any

import anyio
import fakeredis
import httpx
import pytest
from fakeredis import aioredis
from starlette.applications import Starlette

from acp.budget import QuotaCounter, RateLimiter
from acp.budget.redis_store import RedisBudgets
from acp.config import GatewaySettings
from acp.exceptions import ConfigurationError
from acp.gateway import UpstreamRegistry, build_app
from acp.identity import AuthenticationMiddleware
from acp.mocks import mock_a
from acp.runtime import build_budgets, gateway_from_settings
from acp.upstream import UpstreamClient, UpstreamConfig

from ..tokens import Keypair, claims
from .helpers import validator_for
from .test_rate_limiting import MCP_HEADERS, RATE_LIMIT_CODE, _parse

pytestmark = pytest.mark.integration

UPSTREAMS_YAML = """
upstreams:
  - name: mock-a
    url: http://127.0.0.1:9101/mcp
"""


def settings_for(
    *,
    budget_store_url: str = "",
    rate_limit_enabled: bool = True,
    quota_enabled: bool = False,
    upstreams_file: Path | None = None,
) -> GatewaySettings:
    extra: dict[str, Any] = {}
    if upstreams_file is not None:
        extra["upstreams_file"] = upstreams_file
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_required=False,
        health_probing_enabled=False,
        schema_drift_detection_enabled=False,
        rate_limit_enabled=rate_limit_enabled,
        rate_limit_capacity=2,
        rate_limit_refill_per_second=0.001,
        quota_enabled=quota_enabled,
        budget_store_url=budget_store_url,
        **extra,
    )


# ---------------------------------------------------------------------------
# The setting selects the keeper
# ---------------------------------------------------------------------------


def test_no_store_url_builds_no_shared_keeper() -> None:
    assert build_budgets(settings_for()) is None


def test_a_store_url_builds_the_shared_keeper_with_the_configured_limits() -> None:
    keeper = build_budgets(
        settings_for(budget_store_url="redis://redis.test/0", quota_enabled=True)
    )

    assert isinstance(keeper, RedisBudgets)
    assert keeper.capacity == 2
    assert keeper.limit == 10000.0


def test_a_disabled_budget_is_not_charged_to_the_store() -> None:
    keeper = build_budgets(settings_for(budget_store_url="redis://redis.test/0"))

    assert isinstance(keeper, RedisBudgets)
    assert keeper.limit is None, "quota is off; the store must not invent one"


def test_a_store_with_neither_budget_enabled_is_not_opened(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="acp.runtime"):
        keeper = build_budgets(
            settings_for(budget_store_url="redis://redis.test/0", rate_limit_enabled=False)
        )

    assert keeper is None
    assert [r for r in caplog.records if r.message == "budget.store_unused"]


def test_the_store_url_must_be_a_redis_url() -> None:
    with pytest.raises(ValueError, match="ACP_BUDGET_STORE_URL"):
        settings_for(budget_store_url="memcached://cache.test")


def test_an_unreachable_store_refuses_to_start(tmp_path: Path) -> None:
    upstreams_file = tmp_path / "upstreams.yaml"
    upstreams_file.write_text(UPSTREAMS_YAML)
    settings = settings_for(upstreams_file=upstreams_file, budget_store_url="redis://127.0.0.1:1/0")

    async def _run() -> None:
        async with gateway_from_settings(settings):
            pass  # pragma: no cover - never reached

    with pytest.raises(ConfigurationError, match="budget store"):
        anyio.run(_run)


# ---------------------------------------------------------------------------
# Two gateways, one bucket, the real path
# ---------------------------------------------------------------------------


def _codes_across(
    keypair: Keypair, token: str, builders: list[dict[str, Any]], n: int
) -> list[int | None]:
    """``n`` calls round-robin across gateways built with ``builders``' kwargs,
    each a replica with its own upstream pool. The error code of each."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "mock-a__search", "arguments": {"query": "x"}},
    }

    async def _run() -> list[int | None]:
        codes: list[int | None] = []
        async with contextlib.AsyncExitStack() as stack:
            agents: list[httpx.AsyncClient] = []
            for kwargs in builders:
                client = UpstreamClient(
                    UpstreamConfig(name="mock-a", url="http://mock/mcp"),
                    httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_a.app)),
                )
                await stack.enter_async_context(client)
                app: Starlette = build_app(
                    UpstreamRegistry([client]), validator=validator_for(keypair), **kwargs
                )
                app.add_middleware(AuthenticationMiddleware, validator=validator_for(keypair))
                await stack.enter_async_context(app.router.lifespan_context(app))
                agents.append(
                    await stack.enter_async_context(
                        httpx.AsyncClient(
                            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
                        )
                    )
                )
            for i in range(n):
                resp = await agents[i % len(agents)].post(
                    "/mcp", json=body, headers={**MCP_HEADERS, "authorization": f"Bearer {token}"}
                )
                parsed = _parse(resp)
                codes.append(parsed["error"]["code"] if "error" in parsed else None)
        return codes

    return anyio.run(_run)


def test_two_replicas_with_their_own_limiters_hand_out_two_bursts(keypair: Keypair) -> None:
    """The bug, demonstrated on the real path so the fix below is measured
    against it: a capacity-2 bucket per process, two processes, four calls
    served before anybody is refused."""
    token = keypair.sign(claims())
    replicas = [
        {"limiter": RateLimiter(capacity=2, refill_per_second=0.0)},
        {"limiter": RateLimiter(capacity=2, refill_per_second=0.0)},
    ]

    codes = _codes_across(keypair, token, replicas, 5)

    assert codes[:4] == [None, None, None, None]
    assert codes[4] == RATE_LIMIT_CODE


def test_two_replicas_sharing_a_keeper_hand_out_one_burst(keypair: Keypair) -> None:
    """The fix: the same two gateways around one keeper. Two calls served,
    the third refused — whichever replica it lands on."""
    token = keypair.sign(claims())
    server = fakeredis.FakeServer()

    def keeper() -> RedisBudgets:
        return RedisBudgets(
            aioredis.FakeRedis(server=server), capacity=2, refill_per_second=0.0, limit=None
        )

    codes = _codes_across(keypair, token, [{"budgets": keeper()}, {"budgets": keeper()}], 4)

    assert codes == [None, None, RATE_LIMIT_CODE, RATE_LIMIT_CODE]


def test_the_shared_keeper_wins_over_in_memory_budgets_handed_alongside(keypair: Keypair) -> None:
    """`build_app` given both uses the keeper; the limiter and quota beside it
    are never charged. Assembly from settings never passes both, but a test
    harness might, and the rule must be the same either way."""
    token = keypair.sign(claims())
    limiter = RateLimiter(capacity=100, refill_per_second=0.0)
    quota = QuotaCounter(limit=100, window_seconds=60)
    keeper = RedisBudgets(
        aioredis.FakeRedis(server=fakeredis.FakeServer()),
        capacity=1,
        refill_per_second=0.0,
        limit=None,
    )

    codes = _codes_across(
        keypair, token, [{"budgets": keeper, "limiter": limiter, "quota": quota}], 2
    )

    assert codes == [None, RATE_LIMIT_CODE]
    assert limiter.remaining("alice@example.test") == 100
