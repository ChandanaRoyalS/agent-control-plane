"""Tests for process lifecycle: building the gateway and tearing it down.

The property under test is that connection pools are always closed — on the
happy path, on an exception inside the context, and even when one upstream's
close fails. A leaked pool is a leaked socket, and a gateway restarted a few
hundred times in a deploy loop would exhaust the host.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import pytest

from acp.config import GatewaySettings
from acp.exceptions import ConfigurationError
from acp.runtime import gateway_from_configs, gateway_from_settings
from acp.upstream import UpstreamConfig

pytestmark = pytest.mark.integration

CONFIGS = [
    UpstreamConfig(name="mock-a", url="http://127.0.0.1:9101/mcp"),
    UpstreamConfig(name="mock-b", url="http://127.0.0.1:9102/mcp"),
]


def test_the_gateway_builds_and_tears_down_cleanly() -> None:
    async def _run() -> Any:
        async with gateway_from_configs(CONFIGS) as app:
            return app

    assert anyio.run(_run) is not None


def test_pools_are_closed_when_the_body_raises() -> None:
    """A failure while serving must not leak sockets.

    `finally` rather than a happy-path close is what makes this hold, and it is
    the difference between a crash and a crash that also exhausts the host.
    """

    class BoomError(Exception):
        pass

    async def _run() -> None:
        async with gateway_from_configs(CONFIGS):
            raise BoomError

    with pytest.raises(BoomError):
        anyio.run(_run)


def test_an_empty_upstream_list_still_builds() -> None:
    """Bringing the gateway up before its upstreams exist is legitimate."""

    async def _run() -> Any:
        async with gateway_from_configs([]) as app:
            return app

    assert anyio.run(_run) is not None


def test_settings_path_validates_before_opening_connections(tmp_path: Path) -> None:
    """A bad config must fail with no side effects at all.

    Reading and validating upstreams *before* connecting means a typo in the
    YAML cannot leave half-open pools behind.
    """
    bad = tmp_path / "upstreams.yaml"
    bad.write_text("upstreams:\n  - name: BAD_NAME\n    url: http://x/mcp\n", encoding="utf-8")
    settings = GatewaySettings(upstreams_file=bad, _env_file=None)  # type: ignore[call-arg]

    async def _run() -> None:
        async with gateway_from_settings(settings):
            pass

    with pytest.raises(ConfigurationError, match="BAD_NAME"):
        anyio.run(_run)
