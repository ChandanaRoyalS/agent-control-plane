"""Unit tests for catalogue caching.

Most of these are about the two rules that are not performance decisions.

A ``private`` response is one the upstream computed for a particular caller.
Holding it in a cache shared between callers would serve one principal the tool
list belonging to another — the exact failure task 44 exists to prevent, arriving
early and quietly. The MCP SDK's own client cache states the rule outright: only
``public`` entries may be shared across authorization contexts.

And a TTL is input from a system the gateway does not control, so it is clamped.
An upstream advertising a day would otherwise freeze its catalogue for a day.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from acp.exceptions import UpstreamUnavailableError
from acp.upstream import UpstreamConfig
from acp.upstream.cache import MAX_TTL_MS, CachePolicy, CachingUpstreamClient
from acp.upstream.models import ListToolsResult


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeUpstream:
    def __init__(self, *responses: Any) -> None:
        self.config = UpstreamConfig(name="mock-a", url="http://mock/mcp")
        self.responses: list[ListToolsResult | BaseException] = list(responses)
        self.calls = 0
        self.invalidations = 0

    async def list_tools(self) -> ListToolsResult:
        outcome = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def call_tool(self, name: str, arguments: Any = None) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def aclose(self) -> None:  # pragma: no cover
        return None

    async def invalidate(self) -> None:
        self.invalidations += 1


def catalogue(ttl_ms: int = 60_000, scope: str = "public", n: int = 2) -> ListToolsResult:
    return ListToolsResult.model_validate(
        {
            "tools": [{"name": f"tool{i}", "inputSchema": {}} for i in range(n)],
            "ttlMs": ttl_ms,
            "cacheScope": scope,
        }
    )


def run(fn: Any) -> Any:
    return anyio.run(fn)


def cached(
    upstream: FakeUpstream, clock: FakeClock | None = None, **policy: Any
) -> CachingUpstreamClient:
    return CachingUpstreamClient(
        upstream, CachePolicy(**policy) if policy else None, clock=clock or FakeClock()
    )


# ---------------------------------------------------------------------------
# The authorization rule — not a performance decision
# ---------------------------------------------------------------------------


def test_a_private_catalogue_is_never_cached() -> None:
    """`private` means the upstream computed this for a particular caller.

    This gateway has one shared cache and, until task 22, no notion of who is
    asking — so there is exactly one safe thing to do with a private response,
    and it is nothing.
    """
    up = FakeUpstream(catalogue(ttl_ms=60_000, scope="private"))
    client = cached(up)

    async def _run() -> None:
        await client.list_tools()
        await client.list_tools()

    run(_run)

    assert up.calls == 2, "a private catalogue was held in a shared cache"


def test_a_public_catalogue_is_cached() -> None:
    up = FakeUpstream(catalogue(ttl_ms=60_000, scope="public"))
    client = cached(up)

    async def _run() -> None:
        await client.list_tools()
        await client.list_tools()

    run(_run)

    assert up.calls == 1


def test_public_still_requires_a_positive_ttl() -> None:
    """`ttlMs: 0` is the spec's way of saying do not cache, and it means that
    whatever the scope says."""
    up = FakeUpstream(catalogue(ttl_ms=0, scope="public"))
    client = cached(up)

    async def _run() -> None:
        await client.list_tools()
        await client.list_tools()

    run(_run)

    assert up.calls == 2


def test_the_defaults_are_the_conservative_ones() -> None:
    """A response carrying no hints at all is uncacheable. An upstream that
    said nothing has not agreed to anything, and inferring consent from silence
    is how a gateway serves a catalogue its owner never sanctioned."""
    bare = ListToolsResult.model_validate({"tools": []})

    assert bare.ttl_ms == 0
    assert bare.cache_scope == "private"
    assert bare.is_shareable is False


# ---------------------------------------------------------------------------
# Expiry and clamping
# ---------------------------------------------------------------------------


def test_the_entry_expires() -> None:
    clock = FakeClock()
    up = FakeUpstream(catalogue(ttl_ms=60_000))
    client = cached(up, clock)

    async def _run() -> None:
        await client.list_tools()
        clock.advance(59)
        await client.list_tools()
        clock.advance(2)
        await client.list_tools()

    run(_run)

    assert up.calls == 2, "served past its own expiry, or refetched before it"


def test_an_absurd_ttl_is_clamped() -> None:
    """A hint is input from a system the gateway does not control. A year-long
    TTL, by bug or by design, would otherwise mean a year of offering tools that
    stopped existing."""
    clock = FakeClock()
    up = FakeUpstream(catalogue(ttl_ms=365 * 24 * 60 * 60 * 1000))
    client = cached(up, clock, max_ttl_ms=5_000)

    async def _run() -> None:
        await client.list_tools()
        clock.advance(6)
        await client.list_tools()

    run(_run)

    assert up.calls == 2


def test_the_default_ceiling_matches_the_sdk() -> None:
    """Two caches in one system disagreeing about the maximum lifetime of the
    same response is a difference nobody finds until it matters."""
    assert MAX_TTL_MS == 24 * 60 * 60 * 1000
    assert CachePolicy().max_ttl_ms == MAX_TTL_MS


def test_caching_can_be_switched_off_entirely() -> None:
    up = FakeUpstream(catalogue())
    client = cached(up, enabled=False)

    async def _run() -> None:
        await client.list_tools()
        await client.list_tools()

    run(_run)

    assert up.calls == 2


# ---------------------------------------------------------------------------
# Failure, and forgetting
# ---------------------------------------------------------------------------


def test_a_failure_is_not_served_from_a_stale_entry() -> None:
    """No stale-on-error, deliberately.

    Serving a dead upstream's old catalogue would have the agent calling tools
    that cannot work — exactly what task 18's withdrawal exists to prevent. A
    cache entry is a claim about freshness, not a consolation prize.
    """
    clock = FakeClock()
    up = FakeUpstream(catalogue(ttl_ms=60_000), UpstreamUnavailableError("down", upstream="mock-a"))
    client = cached(up, clock)

    async def _run() -> None:
        await client.list_tools()
        clock.advance(61)
        with pytest.raises(UpstreamUnavailableError):
            await client.list_tools()
        # And the expired entry must not resurface afterwards either.
        with pytest.raises(UpstreamUnavailableError):
            await client.list_tools()

    run(_run)


def test_invalidate_forces_the_next_fetch() -> None:
    up = FakeUpstream(catalogue(ttl_ms=60_000))
    client = cached(up)

    async def _run() -> None:
        await client.list_tools()
        await client.invalidate()
        await client.list_tools()

    run(_run)

    assert up.calls == 2


def test_invalidate_reaches_the_layers_below() -> None:
    """The health monitor calls this without knowing which wrappers are
    present, so it has to propagate rather than stop at the outermost cache."""
    up = FakeUpstream(catalogue())
    client = cached(up)

    run(client.invalidate)

    assert up.invalidations == 1


def test_a_tool_call_is_never_cached() -> None:
    """A tool call is an action with effects. A cache returning yesterday's
    answer to `create_ticket` is a bug with consequences, not a stale read.
    Result caching for genuinely idempotent tools is task 43, and it needs the
    per-principal key this layer deliberately does not have."""
    up = FakeUpstream(catalogue())
    client = cached(up)

    async def _run() -> None:
        with pytest.raises(NotImplementedError):
            await client.call_tool("search", {})

    run(_run)


def test_the_cache_reports_its_own_state() -> None:
    """A cache whose contents cannot be observed is one whose behaviour has to
    be inferred from timing."""
    clock = FakeClock()
    up = FakeUpstream(catalogue(ttl_ms=30_000))
    client = cached(up, clock)

    assert client.cached_until is None

    run(client.list_tools)

    assert client.cached_until == pytest.approx(clock.now + 30.0)


def test_the_wrapper_still_looks_like_an_upstream() -> None:
    up = FakeUpstream(catalogue())
    client = cached(up)

    async def _run() -> tuple[str, list[str]]:
        result = await client.list_tools()
        return client.config.name, [t.name for t in result.tools]

    assert run(_run) == ("mock-a", ["tool0", "tool1"])


# ---------------------------------------------------------------------------
# Policy arithmetic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ttl_ms", "scope", "expected"),
    [
        pytest.param(60_000, "public", 60.0, id="honoured"),
        pytest.param(60_000, "private", 0.0, id="private-never"),
        pytest.param(0, "public", 0.0, id="zero-means-no"),
    ],
)
def test_ttl_resolution(ttl_ms: int, scope: str, expected: float) -> None:
    result = ListToolsResult.model_validate({"tools": [], "ttlMs": ttl_ms, "cacheScope": scope})

    assert CachePolicy().ttl_seconds_for(result) == expected


def test_an_explicit_zero_ttl_beats_a_configured_default() -> None:
    """`ttlMs: 0` is an instruction, not an absence.

    The SDK's own cache draws exactly this distinction — "an explicit ttlMs: 0
    stays 0" — and getting it wrong means caching a catalogue whose owner said,
    in as many words, not to. Pydantic's `model_fields_set` is what tells an
    explicit zero apart from a field nobody sent.
    """
    policy = CachePolicy(default_ttl_ms=30_000)
    explicit_zero = ListToolsResult.model_validate(
        {"tools": [], "ttlMs": 0, "cacheScope": "public"}
    )

    assert policy.ttl_seconds_for(explicit_zero) == 0.0


def test_the_default_applies_when_no_hint_was_sent_at_all() -> None:
    """The only case a configured default is entitled to fill in. Note the
    scope still has to be public — a default TTL cannot manufacture consent to
    share something marked private."""
    policy = CachePolicy(default_ttl_ms=30_000)
    silent = ListToolsResult.model_validate({"tools": [], "cacheScope": "public"})

    assert policy.ttl_seconds_for(silent) == 30.0


def test_tools_survive_the_round_trip() -> None:
    """Built by wire alias, as every other test here does — the model is a
    parser for what upstreams send, so constructing it the way the wire does is
    the construction worth exercising."""
    result = ListToolsResult.model_validate(
        {"tools": [{"name": "search"}], "ttlMs": 1000, "cacheScope": "public"}
    )

    assert result.is_shareable is True
    assert [t.name for t in result.tools] == ["search"]
