"""Unit tests for upstream configuration validation.

The name rule is the interesting one: it enforces ADR 0003 structurally rather
than by convention, so an ambiguous qualified tool name becomes impossible to
construct instead of merely discouraged.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from acp.upstream import UpstreamConfig


def test_minimal_config_gets_sensible_defaults() -> None:
    config = UpstreamConfig(name="mock-a", url="http://localhost:9101/mcp")

    assert config.connect_timeout < config.read_timeout, (
        "connect must fail faster than read: an unreachable host should not "
        "occupy a worker for as long as a legitimately slow tool call"
    )
    assert config.max_keepalive_connections <= config.max_connections


@pytest.mark.parametrize("name", ["mock-a", "mockb", "a1", "one-two-three"])
def test_valid_names_are_accepted(name: str) -> None:
    assert UpstreamConfig(name=name, url="http://x/mcp").name == name


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("mock_a", id="underscore-would-make-__-ambiguous"),
        pytest.param("Mock-A", id="uppercase"),
        pytest.param("-leading", id="leading-hyphen"),
        pytest.param("trailing-", id="trailing-hyphen"),
        pytest.param("double--hyphen", id="double-hyphen"),
        pytest.param("", id="empty"),
        pytest.param("has space", id="space"),
    ],
)
def test_invalid_names_are_rejected(name: str) -> None:
    with pytest.raises(ValidationError, match="lowercase alphanumeric"):
        UpstreamConfig(name=name, url="http://x/mcp")


@pytest.mark.parametrize("url", ["ftp://x/mcp", "mock-a/mcp", "//x/mcp", ""])
def test_non_http_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValidationError, match="http"):
        UpstreamConfig(name="mock-a", url=url)


@pytest.mark.parametrize(
    "field", ["connect_timeout", "read_timeout", "write_timeout", "pool_timeout"]
)
def test_non_positive_timeouts_are_rejected(field: str) -> None:
    """A zero or negative timeout is a configuration bug, not a way to disable one."""
    # Typed explicitly: an untyped literal makes mypy infer dict[str, int],
    # which cannot satisfy the tuple-valued fields on the model.
    overrides: dict[str, Any] = {field: 0}

    with pytest.raises(ValidationError):
        UpstreamConfig(name="mock-a", url="http://x/mcp", **overrides)


def test_unknown_fields_are_rejected() -> None:
    """A typo in a config key must fail loudly rather than silently do nothing."""
    with pytest.raises(ValidationError):
        UpstreamConfig(name="mock-a", url="http://x/mcp", read_timout=5)  # type: ignore[call-arg]


def test_the_bulkhead_may_not_be_wider_than_the_connection_pool() -> None:
    """Otherwise the pool saturates first and calls queue for ``pool_timeout``,
    quietly reintroducing the unbounded waiting the bulkhead exists to prevent
    — and reporting it as a timeout rather than as overload."""
    with pytest.raises(ValidationError, match="max_concurrency"):
        UpstreamConfig(name="mock-a", url="http://x/mcp", max_concurrency=50, max_connections=20)


def test_a_bulkhead_narrower_than_the_pool_is_fine() -> None:
    config = UpstreamConfig(
        name="mock-a", url="http://x/mcp", max_concurrency=5, max_connections=20
    )

    assert config.max_concurrency == 5


def test_resilience_defaults_are_conservative() -> None:
    """The defaults are what most upstreams will actually run with, so they are
    worth pinning: no tool call retried, a breaker that needs real evidence
    before opening, and a single probe on the way back."""
    config = UpstreamConfig(name="mock-a", url="http://x/mcp")

    assert config.idempotent_tools == ()
    assert config.failure_threshold > 1, "one blip must not withdraw an upstream"
    assert config.half_open_max_calls == 1
    assert config.max_concurrency <= config.max_connections


@pytest.mark.parametrize("field", ["failure_threshold", "half_open_max_calls", "max_concurrency"])
def test_non_positive_limits_are_rejected(field: str) -> None:
    overrides: dict[str, Any] = {field: 0}

    with pytest.raises(ValidationError):
        UpstreamConfig(name="mock-a", url="http://x/mcp", **overrides)


def test_config_is_frozen() -> None:
    """Config is read at startup and shared across tasks; mutation would be a race."""
    config = UpstreamConfig(name="mock-a", url="http://x/mcp")

    with pytest.raises(ValidationError):
        config.name = "other"
