"""The cache key, which is the whole task, and the cache around it.

Everything here that is not about the key is a dictionary with a size limit.
The key is where a mistake becomes a privilege escalation with excellent p99 —
correct-looking, fast, and invisible to every functional test.
"""

from __future__ import annotations

import time

import anyio
import anyio.lowlevel

from acp.identity.cache import DEFAULT_MAX_ENTRIES, CredentialCache, CredentialKey
from acp.identity.exchange import ExchangedToken

ALICE = "alice.subject.token"
BOB = "bob.subject.token"
MOCK_A = "acp-upstream-mock-a"
MOCK_B = "acp-upstream-mock-b"


def token(audience: str = MOCK_A, *, expires_at: float | None = None) -> ExchangedToken:
    return ExchangedToken(
        access_token=f"credential-for-{audience}",
        audience=audience,
        issuer="https://idp.corp.test/realms/acp",
        expires_at=expires_at,
    )


def key(subject: str = ALICE, audience: str = MOCK_A, resource: str = "") -> CredentialKey:
    return CredentialKey.of(subject, audience, resource)


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------


def test_two_callers_never_share_a_key() -> None:
    """The leak this whole module exists to prevent. Key on the upstream alone
    and alice's credential is served to bob — a privilege escalation that passes
    every functional test and looks like a performance win."""
    assert key(ALICE) != key(BOB)


def test_two_upstreams_never_share_a_key() -> None:
    """The other half. One credential reused across upstreams would hand mock-a
    something that works at mock-b, which is the confused deputy arriving via a
    cache rather than via a token request."""
    assert key(audience=MOCK_A) != key(audience=MOCK_B)


def test_two_resources_never_share_a_key() -> None:
    """`resource` goes to the token endpoint, so it is part of the request, so
    it is part of the key. That it currently changes nothing at Keycloak
    (ADR 0020) is a fact about one server on one date and no basis for leaving
    it out of a cache key."""
    assert key(resource="https://a.internal/mcp") != key(resource="https://b.internal/mcp")


def test_the_same_request_is_the_same_key() -> None:
    """The property that makes caching correct, stated as an equality: identical
    input to the token endpoint means identical output from it."""
    assert key() == key()


def test_the_key_does_not_contain_the_token() -> None:
    """Task 27's invariant is that the inbound token exists in one place with
    one reader. A dictionary key is a second place, and a cache is a structure
    whose whole purpose is to outlive the request that created it."""
    k = key(ALICE)

    assert ALICE not in k.subject_digest
    assert ALICE not in repr(k)
    assert len(k.subject_digest) == 64, "a sha256 hex digest"


def test_a_short_key_is_safe_to_log() -> None:
    """Enough to tell two keys apart in a trace, useless for anything else."""
    assert len(key().short) == 12
    assert key(ALICE).short != key(BOB).short


# ---------------------------------------------------------------------------
# Hits, misses and expiry
# ---------------------------------------------------------------------------


def test_a_stored_credential_comes_back() -> None:
    cache = CredentialCache()
    cache.put(key(), token())

    assert cache.get(key()) is not None


def test_a_credential_for_somebody_else_does_not() -> None:
    cache = CredentialCache()
    cache.put(key(ALICE), token())

    assert cache.get(key(BOB)) is None


def test_an_expired_credential_is_dropped_rather_than_returned() -> None:
    """A caller that receives an expired credential cannot tell it apart from a
    live one, and finds out at the upstream — after any side effect."""
    cache = CredentialCache()
    cache.put(key(), token(expires_at=0.0))

    assert cache.get(key()) is None
    assert len(cache) == 0


def test_expiry_is_judged_with_the_skew_margin() -> None:
    """A token valid when the cache checks it and expired when the upstream does
    fails in the worst possible order. `ExchangedToken.expired` applies the
    margin; this asserts the cache honours it rather than comparing timestamps
    itself."""
    cache = CredentialCache()
    cache.put(key(), token(expires_at=time.time() + 10))

    assert cache.get(key()) is None, "inside the 30s skew margin"


# ---------------------------------------------------------------------------
# Bounded
# ---------------------------------------------------------------------------


def test_the_cache_is_bounded() -> None:
    """A security limit before a memory one: an authenticated caller with a
    token mint can otherwise drive this in a loop and have every entry retained
    until it expires."""
    cache = CredentialCache(max_entries=3)

    for n in range(10):
        cache.put(key(f"token-{n}"), token())

    assert len(cache) == 3


def test_eviction_is_least_recently_used() -> None:
    """The entry evicted should be the one nobody is using, not the one that
    happened to be inserted first — a busy principal should not lose their
    credential to a burst from a quiet one."""
    cache = CredentialCache(max_entries=2)
    cache.put(key("a"), token())
    cache.put(key("b"), token())

    cache.get(key("a"))  # touch it
    cache.put(key("c"), token())  # evicts the least recently used, which is b

    assert cache.get(key("a")) is not None
    assert cache.get(key("b")) is None
    assert cache.get(key("c")) is not None


def test_the_default_bound_is_stated_not_implied() -> None:
    assert CredentialCache()._max_entries == DEFAULT_MAX_ENTRIES


# ---------------------------------------------------------------------------
# Single flight
# ---------------------------------------------------------------------------


def test_one_lock_per_key_rather_than_one_for_everything() -> None:
    """A single global lock would serialise every exchange in the gateway behind
    the slowest one — a latency bug wearing a correctness costume."""
    cache = CredentialCache()

    assert cache.lock_for(key(ALICE)) is not cache.lock_for(key(BOB))


def test_the_same_key_gets_the_same_lock() -> None:
    """Which is what makes concurrent misses collapse into one exchange."""
    cache = CredentialCache()

    assert cache.lock_for(key()) is cache.lock_for(key())


def test_counters_separate_hits_from_misses() -> None:
    """The interesting failure is silent: a key that is too specific still
    returns correct credentials and simply never hits. Nothing breaks; the
    authorization server just takes every request."""
    cache = CredentialCache()
    cache.record(hit=True)
    cache.record(hit=False)
    cache.record(hit=False)

    assert (cache.hits, cache.misses) == (1, 2)


def test_clearing_releases_the_locks_too() -> None:
    """A lock dictionary that grows without its cache is a leak with a longer
    fuse and no symptom until it matters."""
    cache = CredentialCache()
    cache.lock_for(key())
    cache.put(key(), token())

    cache.clear()

    assert len(cache) == 0
    assert cache._locks == {}


def test_eviction_releases_the_lock_for_that_key() -> None:
    cache = CredentialCache(max_entries=1)
    cache.lock_for(key("a"))
    cache.put(key("a"), token())
    cache.put(key("b"), token())

    assert key("a") not in cache._locks


def test_concurrent_use_of_one_lock_serialises() -> None:
    """Sanity: the lock is a real one, not a stub that always yields.

    Driven through `anyio.run` rather than written as an `async def` test, like
    every other async assertion in this project. It keeps the suite independent
    of which asyncio plugin happens to be configured — and the build sandbox has
    a different one from Chandana's machine, which is exactly the sort of skew
    that makes a test pass in one place and not collect in the other.
    """
    order: list[str] = []

    async def _run() -> None:
        cache = CredentialCache()

        async def worker(name: str) -> None:
            async with cache.lock_for(key()):
                order.append(f"{name}-in")
                await anyio.lowlevel.checkpoint()
                order.append(f"{name}-out")

        async with anyio.create_task_group() as group:
            group.start_soon(worker, "a")
            group.start_soon(worker, "b")

    anyio.run(_run)

    assert order in (
        ["a-in", "a-out", "b-in", "b-out"],
        ["b-in", "b-out", "a-in", "a-out"],
    ), f"the two overlapped: {order}"
