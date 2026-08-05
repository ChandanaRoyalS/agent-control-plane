"""Tests for qualified tool naming.

The property-based tests are the point here. Naming is a pure function whose
correctness is defined by invariants — round-tripping, determinism, uniqueness —
and example-based tests systematically miss the boundary where truncation kicks
in, which is exactly where the bugs live.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from acp.gateway.naming import (
    HASH_LENGTH,
    MAX_QUALIFIED_LENGTH,
    SEPARATOR,
    MalformedToolNameError,
    may_be_truncated,
    qualify,
    suffix_of,
    upstream_of,
)

# Mirrors what UpstreamConfig actually allows: lowercase alphanumerics and
# single hyphens, capped at 24 characters.
upstream_names = st.from_regex(r"\A[a-z0-9]{1,10}(-[a-z0-9]{1,5}){0,2}\Z", fullmatch=True)

# Tool names are far less constrained — they come from servers we do not
# control, so the strategy deliberately includes underscores and long names.
tool_names = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="_-"),
    min_size=1,
    max_size=120,
)


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


@given(upstream=upstream_names, tool=tool_names)
def test_qualified_names_never_exceed_the_limit(upstream: str, tool: str) -> None:
    """The whole reason truncation exists."""
    assert len(qualify(upstream, tool)) <= MAX_QUALIFIED_LENGTH


@given(upstream=upstream_names, tool=tool_names)
def test_upstream_is_always_recoverable(upstream: str, tool: str) -> None:
    """Routing must work even when the tool half was mangled.

    This is the invariant the entire routing design rests on.
    """
    assert upstream_of(qualify(upstream, tool)) == upstream


@given(upstream=upstream_names, tool=tool_names)
def test_qualification_is_deterministic(upstream: str, tool: str) -> None:
    """Policy rules and audit records reference these names.

    A name that changed between restarts would silently invalidate both, so
    this must not depend on process state — which rules out the built-in
    `hash()`, as an earlier bug in the mocks demonstrated.
    """
    assert qualify(upstream, tool) == qualify(upstream, tool)


@given(upstream=upstream_names, tool=tool_names)
def test_the_fast_path_is_sound(upstream: str, tool: str) -> None:
    """`may_be_truncated` returning False must be *certain*.

    This is the guarantee the routing fast path depends on: when it says a name
    is intact, using the suffix directly must be safe. A wrong answer here means
    invoking the wrong tool, which is the worst failure this module could have.
    """
    qualified = qualify(upstream, tool)
    if not may_be_truncated(qualified):
        assert suffix_of(qualified) == tool


@given(upstream=upstream_names, tool=tool_names)
def test_truncated_names_are_never_missed(upstream: str, tool: str) -> None:
    """No false negatives: anything actually shortened must be flagged.

    False *positives* are acceptable — a tool named to exactly the limit is
    indistinguishable from a truncated one, and paying for a catalogue lookup
    is the correct response to genuine ambiguity.
    """
    qualified = qualify(upstream, tool)
    if len(f"{upstream}{SEPARATOR}{tool}") > MAX_QUALIFIED_LENGTH:
        assert may_be_truncated(qualified)


@given(upstream=upstream_names, a=tool_names, b=tool_names)
def test_distinct_tools_get_distinct_names(upstream: str, a: str, b: str) -> None:
    """Two tools on one upstream must never collide after truncation.

    Hashing the *full* candidate rather than the truncated remainder is what
    makes this hold for names sharing a long prefix.
    """
    if a != b:
        assert qualify(upstream, a) != qualify(upstream, b)


@given(a=upstream_names, b=upstream_names, tool=tool_names)
def test_the_same_tool_on_two_upstreams_gets_distinct_names(a: str, b: str, tool: str) -> None:
    """The planted `search` collision between mock-a and mock-b."""
    if a != b:
        assert qualify(a, tool) != qualify(b, tool)


# ---------------------------------------------------------------------------
# Concrete cases
# ---------------------------------------------------------------------------


def test_short_names_are_left_alone() -> None:
    assert qualify("mock-a", "read_document") == "mock-a__read_document"


def test_tool_names_containing_the_separator_still_route() -> None:
    """`partition` splits on the *first* separator, so this is unambiguous.

    Upstream names cannot contain underscores, so a `__` inside the tool half
    can never be mistaken for the boundary.
    """
    qualified = qualify("mock-a", "get__thing")

    assert qualified == "mock-a__get__thing"
    assert upstream_of(qualified) == "mock-a"
    assert suffix_of(qualified) == "get__thing"


def test_long_names_are_truncated_with_a_hash() -> None:
    tool = "a" * 100
    qualified = qualify("mock-a", tool)

    assert len(qualified) == MAX_QUALIFIED_LENGTH
    assert qualified.startswith("mock-a__")
    assert may_be_truncated(qualified)
    # `-` plus HASH_LENGTH hex characters at the end
    assert len(qualified.rsplit("-", 1)[1]) == HASH_LENGTH


def test_truncated_names_sharing_a_prefix_differ() -> None:
    """The failure mode truncation would cause if the hash were of the suffix."""
    first = qualify("mock-a", "a" * 100 + "_one")
    second = qualify("mock-a", "a" * 100 + "_two")

    assert first != second


def test_unqualified_name_is_rejected() -> None:
    with pytest.raises(MalformedToolNameError, match="not qualified"):
        upstream_of("read_document")


def test_name_with_empty_upstream_is_rejected() -> None:
    with pytest.raises(MalformedToolNameError):
        upstream_of("__read_document")


def test_upstream_name_leaving_no_room_is_rejected() -> None:
    """Guards the config cap: an over-long upstream must fail loudly.

    `UpstreamConfig` caps names at 24 characters precisely so this cannot
    happen in practice, but the invariant is asserted here rather than assumed.
    """
    with pytest.raises(ValueError, match="no room"):
        qualify("x" * 60, "some_tool")
