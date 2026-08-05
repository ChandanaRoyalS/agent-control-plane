"""Integration tests for catalogue merging and call routing.

Drives both mock upstreams at once, which is the first time the planted `search`
collision between mock-a and mock-b actually has to be resolved rather than
merely noted.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import UnknownToolError, UnknownUpstreamError, UpstreamError
from acp.gateway import naming
from acp.gateway.registry import UpstreamRegistry
from acp.mocks import mock_a, mock_b
from acp.mocks.chaos import CHAOS_MODE_HEADER
from acp.mocks.jsonrpc import CallToolResult as MockResult
from acp.mocks.jsonrpc import TextContent
from acp.mocks.server import MockTool, build_mock_app
from acp.upstream import UpstreamClient, UpstreamConfig

pytestmark = pytest.mark.integration


def client_for(app: Any, name: str, *, chaos: str | None = None) -> UpstreamClient:
    headers = {CHAOS_MODE_HEADER: chaos} if chaos else {}
    return UpstreamClient(
        UpstreamConfig(name=name, url="http://mock/mcp"),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), headers=headers),
    )


def registry(*, a_chaos: str | None = None, b_chaos: str | None = None) -> UpstreamRegistry:
    return UpstreamRegistry(
        [
            client_for(mock_a.app, "mock-a", chaos=a_chaos),
            client_for(mock_b.app, "mock-b", chaos=b_chaos),
        ]
    )


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------


def test_catalogue_merges_both_upstreams_under_qualified_names() -> None:
    async def _run() -> list[str]:
        reg = registry()
        catalogue = await reg.list_tools()
        return [t.name for t in catalogue.tools]

    names = run(_run)

    assert names == [
        "mock-a__read_document",
        "mock-a__search",
        "mock-a__create_ticket",
        "mock-b__search",
        "mock-b__summarize",
        "mock-b__list_channels",
    ]


def test_the_planted_collision_resolves_to_two_distinct_tools() -> None:
    """Both upstreams expose `search`. Neither may shadow the other.

    This is what ADR 0003's namespacing exists for, and the reason the
    collision was planted in the mocks in the first place.
    """

    async def _run() -> list[str]:
        catalogue = await registry().list_tools()
        return [t.name for t in catalogue.tools if t.name.endswith("__search")]

    assert run(_run) == ["mock-a__search", "mock-b__search"]


def test_merged_tools_keep_their_own_schemas() -> None:
    """Qualification must rename, not homogenise.

    mock-a's `search` takes `limit`; mock-b's takes `channel`. If merging lost
    that, an agent would send arguments the upstream rejects.
    """

    async def _run() -> dict[str, Any]:
        catalogue = await registry().list_tools()
        return {t.name: t.input_schema for t in catalogue.tools if t.name.endswith("__search")}

    schemas = run(_run)

    assert "limit" in schemas["mock-a__search"]["properties"]
    assert "channel" in schemas["mock-b__search"]["properties"]


def test_catalogue_ordering_is_deterministic() -> None:
    """Upstreams are fetched concurrently, so completion order is arbitrary.

    The merged catalogue must not inherit that non-determinism, or the tool
    list an agent sees would shuffle between identical requests.
    """

    async def _run() -> list[list[str]]:
        return [[t.name for t in (await registry().list_tools()).tools] for _ in range(5)]

    runs = run(_run)
    assert all(r == runs[0] for r in runs)


# ---------------------------------------------------------------------------
# Partial failure
# ---------------------------------------------------------------------------


def test_one_failing_upstream_does_not_lose_the_other() -> None:
    """The design decision: serve what you can, report what you cannot.

    A gateway that goes dark because one of several upstreams is down is worse
    than one serving the rest.
    """

    async def _run() -> tuple[list[str], dict[str, UpstreamError]]:
        catalogue = await registry(a_chaos="error").list_tools()
        return [t.name for t in catalogue.tools], catalogue.failures  # type: ignore[return-value]

    names, failures = run(_run)

    assert all(n.startswith("mock-b__") for n in names)
    assert len(names) == 3
    assert "mock-a" in failures
    assert "mock-b" not in failures


def test_every_upstream_failing_is_reported_as_a_total_failure() -> None:
    """Distinct from "upstreams that legitimately expose no tools"."""

    async def _run() -> Any:
        return await registry(a_chaos="error", b_chaos="error").list_tools()

    catalogue = run(_run)

    assert catalogue.tools == []
    assert set(catalogue.failures) == {"mock-a", "mock-b"}
    assert catalogue.is_total_failure


def test_a_healthy_but_empty_catalogue_is_not_a_total_failure() -> None:
    async def _run() -> Any:
        return await UpstreamRegistry([]).list_tools()

    catalogue = run(_run)

    assert catalogue.tools == []
    assert not catalogue.is_total_failure


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def test_calls_route_to_the_owning_upstream() -> None:
    async def _run() -> tuple[str, str]:
        reg = registry()
        a = await reg.call_tool("mock-a__search", {"query": "deploy"})
        b = await reg.call_tool("mock-b__search", {"query": "payment"})
        return a.text(), b.text()

    from_a, from_b = run(_run)

    assert from_a.startswith("mock-a search results:")
    assert from_b.startswith("mock-b search results:")


def test_routing_needs_no_prior_list_tools() -> None:
    """Statelessness check: a cold instance must route as well as a warm one.

    Untruncated names resolve purely from the string, so no catalogue read is
    needed at all.
    """

    async def _run() -> str:
        result = await registry().call_tool("mock-a__read_document", {"path": "runbooks/deploy.md"})
        return result.text()

    assert "Deploy runbook" in run(_run)


def test_unknown_upstream_is_rejected_without_calling_anything() -> None:
    async def _run() -> None:
        await registry().call_tool("mock-z__search", {"query": "x"})

    with pytest.raises(UnknownUpstreamError) as exc_info:
        run(_run)

    assert exc_info.value.details["configured"] == ["mock-a", "mock-b"]
    assert exc_info.value.recoverable is False


def test_unqualified_tool_name_is_rejected() -> None:
    async def _run() -> None:
        await registry().call_tool("search", {"query": "x"})

    with pytest.raises(naming.MalformedToolNameError):
        run(_run)


def test_execution_failure_still_returns_as_a_result() -> None:
    """Routing must not turn a tool failure into a routing failure."""

    async def _run() -> Any:
        return await registry().call_tool("mock-a__read_document", {"path": "nope.md"})

    result = run(_run)

    assert result.is_error is True
    assert "no such document" in result.text()


# ---------------------------------------------------------------------------
# Truncated names
# ---------------------------------------------------------------------------


def test_a_truncated_name_is_resolved_through_the_catalogue() -> None:
    """The lossy path: the real name cannot be read off the qualified one.

    Uses a purpose-built upstream whose tool name is long enough to force
    truncation, then calls it by the qualified name a client would have been
    given.
    """
    long_tool = "read_a_document_with_an_extremely_long_and_descriptive_name"
    qualified = naming.qualify("mock-a", long_tool)

    assert naming.may_be_truncated(qualified), "fixture must actually force truncation"
    assert naming.suffix_of(qualified) != long_tool, "and must genuinely lose information"

    app = build_mock_app(
        "mock-a",
        [
            MockTool(
                name=long_tool,
                description="a tool with an inconveniently long name",
                input_schema={"type": "object", "properties": {}},
                handler=lambda _args: MockResult(content=[TextContent(text="resolved correctly")]),
            )
        ],
    )

    async def _run() -> str:
        reg = UpstreamRegistry([client_for(app, "mock-a")])
        result = await reg.call_tool(qualified, {})
        return result.text()

    assert run(_run) == "resolved correctly"


def test_an_unresolvable_truncated_name_is_rejected() -> None:
    """A name at the length limit that no tool on the upstream produces."""
    bogus = "mock-a__" + "z" * (naming.MAX_QUALIFIED_LENGTH - len("mock-a__"))

    assert naming.may_be_truncated(bogus)

    async def _run() -> None:
        await registry().call_tool(bogus, {})

    with pytest.raises(UnknownToolError):
        run(_run)
