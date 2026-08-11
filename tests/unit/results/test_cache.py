"""The result cache key, which is the whole task, and the cache around it.

Everything here that is not about the key is a dictionary with a size limit and
a clock. The key is where a mistake becomes a data breach whose only artefact is
its absence — no credential involved, no anomalous log line, and an upstream
audit trail that is not merely silent but *wrong*, because it records one read
by the person who happened to ask first.
"""

from __future__ import annotations

import pytest

from acp.results.cache import (
    DEFAULT_MAX_ENTRIES,
    KEY_VERSION,
    ResultCache,
    ResultKey,
    key_for,
)
from acp.upstream.models import CallToolResult, ContentBlock

ALICE = "alice@example.test"
BOB = "bob@example.test"
AGENT = "agent-7"
UPSTREAM = "mock-a"
TOOL = "mock-a__search"


def result(text: str = "ok", *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[ContentBlock(type="text", text=text)], isError=is_error)


def key(
    subject: str = ALICE,
    actor: str | None = AGENT,
    upstream: str = UPSTREAM,
    tool: str = TOOL,
    arguments: dict[str, object] | None = None,
) -> ResultKey:
    made = key_for(
        subject=subject,
        actor=actor,
        upstream=upstream,
        tool=tool,
        arguments=arguments if arguments is not None else {"query": "retention"},
    )
    assert made is not None
    return made


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------


def test_two_callers_never_share_a_key() -> None:
    """The breach this whole module exists to prevent.

    Key on the tool and the arguments — what every general-purpose cache
    decorator does — and bob's identical search returns alice's records. Nothing
    fails, nothing logs, and the upstream's audit trail says alice read it.
    """
    assert key(subject=ALICE) != key(subject=BOB)


def test_two_agents_acting_for_one_person_never_share_a_key() -> None:
    """Deliberate over-specificity, and the reason is that this gateway's whole
    model is an agent acting *for* a human. An upstream may legitimately scope by
    which agent — a support bot that sees redacted fields, a research agent
    restricted to public records — and collapsing those into one entry serves one
    agent an answer computed for another's entitlements."""
    assert key(actor="agent-7") != key(actor="agent-9")


def test_a_delegated_call_and_a_direct_one_never_share_a_key() -> None:
    """`None` is an actor value like any other, not an absence to be skipped."""
    assert key(actor=None) != key(actor=AGENT)


def test_two_upstreams_never_share_a_key() -> None:
    assert key(upstream="mock-a") != key(upstream="mock-b")


def test_two_tools_never_share_a_key() -> None:
    assert key(tool="mock-a__search") != key(tool="mock-a__read_document")


def test_two_argument_sets_never_share_a_key() -> None:
    assert key(arguments={"query": "a"}) != key(arguments={"query": "b"})


def test_argument_order_does_not_change_the_key() -> None:
    """A hit-rate property, not a safety one — two spellings of the same call
    hashing differently is a miss, never a leak. Worth asserting anyway, because
    a cache that never hits is a cache nobody notices is broken."""
    assert key(arguments={"a": 1, "b": 2}) == key(arguments={"b": 2, "a": 1})


def test_the_same_call_from_the_same_person_is_the_same_key() -> None:
    assert key() == key()


def test_no_field_can_be_made_to_look_like_the_next_one() -> None:
    """The canonicalisation bug, closed for free.

    Joining the parts with a separator would let a subject containing that
    separator forge a different caller's key. Encoding the parts as a JSON list
    makes the boundaries structural rather than textual.
    """
    forged = key(subject='alice@example.test","agent-7', actor=None)

    assert forged != key(subject=ALICE, actor=AGENT)


def test_the_key_carries_no_subject_and_no_arguments() -> None:
    """A cache key is exactly the sort of thing that ends up in a debug log, and
    the arguments are the caller's own data — a search query, a record id, a
    customer name."""
    made = key(arguments={"query": "acquisition-of-northwind"})

    assert ALICE not in made.digest
    assert "northwind" not in made.digest
    assert ALICE not in repr(made)
    assert len(made.digest) == 64, "a sha256 hex digest"


def test_a_short_key_is_safe_to_log() -> None:
    assert len(key().short) == 12
    assert key(subject=ALICE).short != key(subject=BOB).short


def test_the_key_is_versioned() -> None:
    """So the encoding can change without an entry written under the old scheme
    being read under the new one — the one failure a cache must never have."""
    assert KEY_VERSION == "acp-result-v1"


def test_arguments_that_will_not_encode_are_not_cached() -> None:
    """Refusing is the only correct answer. A fallback to `repr()` can map two
    different argument sets onto one string, and a key collision between two
    callers costs the thing this module exists to prevent. A miss costs a round
    trip."""
    assert (
        key_for(
            subject=ALICE, actor=AGENT, upstream=UPSTREAM, tool=TOOL, arguments={"when": object()}
        )
        is None
    )


def test_a_nan_argument_is_not_cached() -> None:
    """`NaN` is not JSON, and `allow_nan` would emit a token no other parser
    accepts — a value that round-trips within this process and nowhere else."""
    assert (
        key_for(
            subject=ALICE, actor=AGENT, upstream=UPSTREAM, tool=TOOL, arguments={"n": float("nan")}
        )
        is None
    )


# ---------------------------------------------------------------------------
# Hits, misses and expiry
# ---------------------------------------------------------------------------


def test_a_stored_result_comes_back() -> None:
    cache = ResultCache()
    cache.put(key(), result("first"), ttl=30)

    held = cache.get(key())

    assert held is not None
    assert held.text() == "first"


def test_a_result_for_somebody_else_does_not() -> None:
    """The same assertion as the key test, made through the cache, because the
    key being right and the lookup using it are two different facts."""
    cache = ResultCache()
    cache.put(key(subject=ALICE), result("alice's records"), ttl=30)

    assert cache.get(key(subject=BOB)) is None


def test_an_expired_result_is_dropped_rather_than_returned() -> None:
    now = [1000.0]
    cache = ResultCache(clock=lambda: now[0])
    cache.put(key(), result(), ttl=30)

    now[0] += 31

    assert cache.get(key()) is None
    assert len(cache) == 0


def test_a_failed_tool_call_is_never_cached() -> None:
    """A tool that ran and failed is a fact about one moment — a rate limit
    upstream, a record briefly locked, a transient dependency. Caching it turns
    a blip into a minute of guaranteed failure for everybody sharing the key."""
    cache = ResultCache()
    cache.put(key(), result("upstream is unwell", is_error=True), ttl=30)

    assert cache.get(key()) is None
    assert len(cache) == 0


def test_a_zero_ttl_stores_nothing() -> None:
    """So a table entry of zero means "do not cache" without a second way to
    say it."""
    cache = ResultCache()
    cache.put(key(), result(), ttl=0)

    assert len(cache) == 0


def test_a_caller_cannot_edit_what_the_next_caller_receives() -> None:
    """`CallToolResult` is mutable, so handing out a reference to one shared
    model means a caller that edits its answer edits everybody's. Corruption
    that arrives looking like the upstream's own response is worse than no cache
    at all."""
    cache = ResultCache()
    cache.put(key(), result("original"), ttl=30)

    first = cache.get(key())
    assert first is not None
    first.content[0].text = "tampered"

    second = cache.get(key())
    assert second is not None
    assert second.text() == "original"


def test_storing_takes_a_copy_too() -> None:
    """The same hazard from the other side: the caller still holds the object it
    handed over."""
    cache = ResultCache()
    stored = result("original")
    cache.put(key(), stored, ttl=30)

    stored.content[0].text = "tampered after the fact"

    held = cache.get(key())
    assert held is not None
    assert held.text() == "original"


# ---------------------------------------------------------------------------
# Bounded
# ---------------------------------------------------------------------------


def test_the_cache_is_bounded() -> None:
    """A security limit before a memory one: an authenticated caller chooses the
    keys, so varying one argument in a loop retains every distinct call until it
    expires."""
    cache = ResultCache(max_entries=3)

    for n in range(10):
        cache.put(key(arguments={"query": str(n)}), result(), ttl=30)

    assert len(cache) == 3


def test_eviction_is_least_recently_used() -> None:
    cache = ResultCache(max_entries=2)
    cache.put(key(arguments={"q": "a"}), result("a"), ttl=30)
    cache.put(key(arguments={"q": "b"}), result("b"), ttl=30)

    cache.get(key(arguments={"q": "a"}))  # touch it
    cache.put(key(arguments={"q": "c"}), result("c"), ttl=30)

    assert cache.get(key(arguments={"q": "a"})) is not None
    assert cache.get(key(arguments={"q": "b"})) is None
    assert cache.get(key(arguments={"q": "c"})) is not None


def test_the_default_bound_is_stated_not_implied() -> None:
    assert ResultCache()._max_entries == DEFAULT_MAX_ENTRIES


def test_counters_separate_hits_from_misses() -> None:
    """The interesting failure is silent: a key that is too *specific* still
    returns correct results and simply never hits. Nothing breaks; the estate
    just serves every call."""
    cache = ResultCache()
    cache.record(hit=True)
    cache.record(hit=False)

    assert (cache.hits, cache.misses) == (1, 1)


def test_clearing_empties_it() -> None:
    cache = ResultCache()
    cache.put(key(), result(), ttl=30)

    cache.clear()

    assert len(cache) == 0


@pytest.mark.parametrize("ttl", [-1.0, -0.001])
def test_a_negative_ttl_stores_nothing(ttl: float) -> None:
    cache = ResultCache()
    cache.put(key(), result(), ttl=ttl)

    assert len(cache) == 0
