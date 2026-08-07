"""Unit tests for the JWKS cache.

Driven through a real `httpx.MockTransport` rather than by stubbing the client,
so the code under test makes an actual HTTP request against an actual response
object. The behaviours that matter here are all about *how often* it fetches,
and a stub that counts calls to a method it invented would prove nothing about
the client.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import AuthenticationError, IdentityProviderUnavailableError
from acp.identity.keys import JwksCache

from ...tokens import Keypair


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Provider:
    """A stand-in identity provider whose key set can be changed underneath."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document
        self.fetches = 0
        self.status = 200

    def transport(self) -> httpx.MockTransport:
        def handle(_request: httpx.Request) -> httpx.Response:
            self.fetches += 1
            if self.status != 200:
                return httpx.Response(self.status, text="nope")
            return httpx.Response(200, json=self.document)

        return httpx.MockTransport(handle)


def cache(provider: Provider, clock: FakeClock | None = None, **kwargs: Any) -> JwksCache:
    return JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=provider.transport()),
        clock=clock or FakeClock(),
        **kwargs,
    )


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


def test_the_key_set_is_fetched_once_and_reused(keypair: Keypair) -> None:
    provider = Provider(keypair.jwks())
    keys = cache(provider)

    async def _run() -> None:
        for _ in range(5):
            await keys.key_for(keypair.kid)

    run(_run)

    assert provider.fetches == 1


def test_the_key_set_is_refetched_once_its_ttl_expires(keypair: Keypair) -> None:
    """Proactive, so a planned rotation is picked up before anyone presents a
    token signed by the new key."""
    clock = FakeClock()
    provider = Provider(keypair.jwks())
    keys = cache(provider, clock, ttl=600.0)

    async def _run() -> None:
        await keys.key_for(keypair.kid)
        clock.advance(300)
        await keys.key_for(keypair.kid)
        clock.advance(400)
        await keys.key_for(keypair.kid)

    run(_run)

    assert provider.fetches == 2


def test_a_rotated_key_is_picked_up_on_a_miss(keypair: Keypair, other_keypair: Keypair) -> None:
    provider = Provider(keypair.jwks())
    keys = cache(provider, min_refresh_interval=0.0)

    async def _run() -> Any:
        await keys.key_for(keypair.kid)
        provider.document = other_keypair.jwks()
        return await keys.key_for(other_keypair.kid)

    assert run(_run) is not None
    assert provider.fetches == 2


# ---------------------------------------------------------------------------
# Not being a lever
# ---------------------------------------------------------------------------


def test_an_unknown_kid_does_not_refetch_every_time(keypair: Keypair) -> None:
    """The `kid` comes from the token, so it comes from the attacker. A cache
    that refetches on every miss turns "send tokens with random kids" into an
    unauthenticated request amplifier pointed at the identity provider, with the
    gateway paying the latency."""
    clock = FakeClock()
    provider = Provider(keypair.jwks())
    keys = cache(provider, clock, min_refresh_interval=30.0)

    async def _run() -> None:
        await keys.key_for(keypair.kid)
        for index in range(50):
            with pytest.raises(AuthenticationError):
                await keys.key_for(f"forged-{index}")

    run(_run)

    assert provider.fetches == 1, "a flood of unknown kids became a flood of fetches"


def test_the_refresh_floor_lifts_once_the_interval_passes(keypair: Keypair) -> None:
    """Rate limited, not disabled. A real rotation that happens to follow a
    flood must still be picked up."""
    clock = FakeClock()
    provider = Provider(keypair.jwks())
    keys = cache(provider, clock, min_refresh_interval=30.0)

    async def _run() -> None:
        await keys.key_for(keypair.kid)
        with pytest.raises(AuthenticationError):
            await keys.key_for("unknown")
        clock.advance(31)
        with pytest.raises(AuthenticationError):
            await keys.key_for("unknown")

    run(_run)

    assert provider.fetches == 2


def test_a_burst_of_misses_produces_one_fetch(keypair: Keypair, other_keypair: Keypair) -> None:
    """When a key genuinely rotates, every in-flight request misses at the same
    instant. Without a lock they all fetch — the same thundering herd the
    bulkhead exists to prevent one layer down."""
    provider = Provider(keypair.jwks())
    keys = cache(provider, min_refresh_interval=0.0)

    async def _run() -> None:
        await keys.key_for(keypair.kid)
        provider.document = other_keypair.jwks()

        async with anyio.create_task_group() as tg:
            for _ in range(20):
                tg.start_soon(keys.key_for, other_keypair.kid)

    run(_run)

    assert provider.fetches == 2


# ---------------------------------------------------------------------------
# Choosing a key
# ---------------------------------------------------------------------------


def test_a_token_with_no_kid_works_when_there_is_one_key(keypair: Keypair) -> None:
    provider = Provider(keypair.jwks())
    keys = cache(provider)

    assert run(lambda: keys.key_for(None)) is not None


def test_a_token_with_no_kid_is_refused_when_the_choice_is_ambiguous(
    keypair: Keypair, other_keypair: Keypair
) -> None:
    """Trying each key in turn would work, and would also be a signature oracle
    costing one public-key operation per key per attempt — an attacker-controlled
    multiplier on the most expensive thing the gateway does."""
    both = {"keys": [*keypair.jwks()["keys"], *other_keypair.jwks()["keys"]]}
    keys = cache(Provider(both), min_refresh_interval=0.0)

    with pytest.raises(AuthenticationError):
        run(lambda: keys.key_for(None))


# ---------------------------------------------------------------------------
# When the provider is broken
# ---------------------------------------------------------------------------


def test_an_unreachable_provider_is_not_reported_as_a_bad_token(keypair: Keypair) -> None:
    provider = Provider(keypair.jwks())
    provider.status = 503
    keys = cache(provider)

    with pytest.raises(IdentityProviderUnavailableError):
        run(lambda: keys.key_for(keypair.kid))


def test_a_stale_key_set_is_not_served_when_a_refresh_fails(keypair: Keypair) -> None:
    """Deliberately no stale-on-error, and for a sharper reason than the
    catalogue cache's: a gateway that keeps validating tokens against keys it
    can no longer confirm is a gateway that cannot be told a key was revoked,
    and revocation is what key rotation exists to make possible."""
    clock = FakeClock()
    provider = Provider(keypair.jwks())
    keys = cache(provider, clock, ttl=60.0)

    async def _run() -> None:
        await keys.key_for(keypair.kid)
        provider.status = 500
        clock.advance(61)
        with pytest.raises(IdentityProviderUnavailableError):
            await keys.key_for(keypair.kid)

    run(_run)


def test_an_unparseable_key_set_is_refused() -> None:
    keys = cache(Provider({"not": "a key set"}))

    with pytest.raises(IdentityProviderUnavailableError):
        run(lambda: keys.key_for("anything"))


def test_an_empty_key_set_is_refused() -> None:
    keys = cache(Provider({"keys": []}))

    with pytest.raises(IdentityProviderUnavailableError):
        run(lambda: keys.key_for("anything"))


def test_the_error_does_not_disclose_which_keys_exist(keypair: Keypair) -> None:
    """An unknown `kid` is told it is unknown, not which ones are known —
    enumerating the provider's key ids through the gateway would be a small
    gift to somebody mapping the estate."""
    keys = cache(Provider(keypair.jwks()))

    with pytest.raises(AuthenticationError) as caught:
        run(lambda: keys.key_for("who-knows"))

    assert keypair.kid not in str(caught.value.to_jsonrpc_error())
