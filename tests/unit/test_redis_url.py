"""What every Redis this gateway talks to has in common (ADR 0070).

Two things, both of which the first release with Redis got wrong: a client
with no timeouts, which turns a hung server into a hung gateway, and the
library's own errors reaching the request path, where they became an
internal error on one store and an unbounded wait on the other. One client
factory, one wrapper, both stores.
"""

from __future__ import annotations

import fakeredis
import pytest
from fakeredis import aioredis
from redis.exceptions import ConnectionError as RedisConnectionError

from acp.approvals.record import request_for
from acp.approvals.redis_store import RedisApprovalStore
from acp.budget.redis_store import RedisBudgets
from acp.exceptions import StateStoreUnavailableError
from acp.redis_url import (
    COMMAND_TIMEOUT_SECONDS,
    CONNECT_TIMEOUT_SECONDS,
    MAX_CONNECTIONS,
    check_redis_url,
    client_for,
    unavailable,
)


def test_the_client_has_timeouts_and_a_pool_ceiling() -> None:
    """A client that waits forever on a hung Redis holds every budgeted or held
    call behind it. These are the numbers the stores are built with, read back
    from the client rather than trusted from the factory."""
    client = client_for("redis://redis.test:6379/0")
    kwargs = client.connection_pool.connection_kwargs

    assert kwargs["socket_timeout"] == COMMAND_TIMEOUT_SECONDS
    assert kwargs["socket_connect_timeout"] == CONNECT_TIMEOUT_SECONDS
    assert kwargs["health_check_interval"] > 0
    assert client.connection_pool.max_connections == MAX_CONNECTIONS


def test_both_stores_build_their_client_through_the_factory() -> None:
    approvals = RedisApprovalStore.from_url("redis://redis.test/0")
    budgets = RedisBudgets.from_url("redis://redis.test/0", capacity=1.0, limit=None)

    for store in (approvals, budgets):
        kwargs = store._redis.connection_pool.connection_kwargs
        assert kwargs["socket_timeout"] == COMMAND_TIMEOUT_SECONDS


async def test_a_library_error_becomes_the_gateways_one_refusal() -> None:
    with pytest.raises(StateStoreUnavailableError) as refused:
        async with unavailable("budget"):
            raise RedisConnectionError("Connection refused")

    assert refused.value.recoverable is True
    assert "budget" not in refused.value.message, "the wire message names no subsystem"


async def test_a_bug_is_not_dressed_as_unavailability() -> None:
    with pytest.raises(KeyError):
        async with unavailable("budget"):
            raise KeyError("a programming error")


def _down() -> fakeredis.FakeServer:
    server = fakeredis.FakeServer()
    server.connected = False
    return server


async def test_a_budget_charge_against_a_down_store_is_refused_not_served() -> None:
    """Fail closed, legibly. Before this the library's ConnectionError reached
    the SDK as an internal error; the call was still refused, by accident."""
    budgets = RedisBudgets(aioredis.FakeRedis(server=_down()), capacity=10.0, limit=None)

    with pytest.raises(StateStoreUnavailableError):
        await budgets.charge("alice", 1.0, mono=0.0, wall=0.0)


async def test_an_approval_read_against_a_down_store_is_refused() -> None:
    store = RedisApprovalStore(aioredis.FakeRedis(server=_down()))
    request = request_for(
        tenant=None, subject="alice", actor=None, tool="t", arguments={}, rule="r", now=0.0
    )
    assert request is not None

    with pytest.raises(StateStoreUnavailableError):
        await store.create(request)
    with pytest.raises(StateStoreUnavailableError):
        await store.get(request.token)
    with pytest.raises(StateStoreUnavailableError):
        await store.pending()


def test_the_url_check_names_the_setting() -> None:
    with pytest.raises(ValueError, match="ACP_BUDGET_STORE_URL"):
        check_redis_url("ACP_BUDGET_STORE_URL", "http://not-redis")
    assert check_redis_url("ACP_BUDGET_STORE_URL", "") == ""
