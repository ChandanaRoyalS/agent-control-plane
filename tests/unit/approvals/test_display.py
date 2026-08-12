"""What an operator is shown, and why it is the same bytes that bind the call.

Task 55. Task 54 held a call and recorded a fingerprint of it; nothing recorded
what the call *was*, so the only thing an approval channel could have offered a
human was a tool name and a hex digest. **An approval you cannot read is not an
approval** — it is a rubber stamp with extra ceremony — so the record now carries
the canonical arguments themselves.

That is a deliberate departure from ADR 0045, which keeps argument *values* out
of the decision log, and the departure is about the reader rather than the data.
The log is durable, widely readable and shipped to vendors. This record lives in
memory for five minutes and is read by exactly the person being asked to decide
about this one call. Different reader, different threat model, opposite answer.

The property these tests exist for: **what is displayed is what is
fingerprinted**, byte for byte, because a second encoder for display is the one
place "approve the call you read" and "approve the call that runs" could come
apart.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from acp.approvals import (
    MAX_DISPLAYED_ARGUMENT_BYTES,
    ApprovalRequest,
    canonical,
    fingerprint,
    request_for,
)

SUBJECT = "alice@example.test"
TOOL = "crm__delete-record"


def held(arguments: Mapping[str, object], *, now: float = 0.0) -> ApprovalRequest:
    """One held request for these arguments.

    ``Mapping`` rather than ``dict``, for the reason `helpers.rpc` already gives
    about its own parameter: ``dict`` is invariant in its value type, so a caller
    holding a ``dict[str, str]`` cannot pass it to a ``dict[str, object]``
    parameter. ``Mapping`` is covariant there, which is what makes ordinary call
    sites work.
    """
    request = request_for(
        subject=SUBJECT,
        actor=None,
        tool=TOOL,
        arguments=arguments,
        rule="approve-deletes",
        now=now,
    )
    assert request is not None
    return request


# ---------------------------------------------------------------------------
# canonical
# ---------------------------------------------------------------------------


def test_key_order_does_not_change_the_encoding() -> None:
    """Two spellings of one call must be one string, or the fingerprint would
    depend on how a client happened to serialise its dictionary."""
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})


def test_the_encoding_carries_no_insignificant_whitespace() -> None:
    assert canonical({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_something_json_cannot_represent_has_no_encoding() -> None:
    """``None`` rather than a `repr()` fallback. A fallback can map two different
    argument sets onto one string, and here that is not a cache collision but a
    human's yes applied to a call they never saw."""
    assert canonical({"when": object()}) is None


def test_a_call_that_cannot_be_encoded_is_not_held() -> None:
    """Refused outright rather than held without a display, because an approval
    that cannot be bound to a call is an approval for anything."""
    assert (
        request_for(
            subject=SUBJECT,
            actor=None,
            tool=TOOL,
            arguments={"when": object()},
            rule=None,
            now=0.0,
        )
        is None
    )


# ---------------------------------------------------------------------------
# The property this is all for
# ---------------------------------------------------------------------------


def test_the_stored_arguments_are_the_fingerprinted_ones() -> None:
    """**The assertion this file exists for.**

    Not "the record contains the arguments" — that a display and a binding are
    produced by the same encoder, so no edit can make them disagree without
    breaking this.
    """
    arguments = {"dataset": "production", "confirm": True}
    request = held(arguments)

    assert request.arguments_json == canonical(arguments)
    assert request.fingerprint == fingerprint(
        subject=SUBJECT, actor=None, tool=TOOL, arguments=arguments
    )


def test_the_stored_form_parses_back_to_what_was_asked() -> None:
    arguments = {"dataset": "production", "rows": [1, 2, 3]}
    request = held(arguments)

    # Narrowed rather than cast: the field is `str | None` because a call can be
    # too large to display, and a test that reached past that would be asserting
    # against a type the code does not promise.
    assert request.arguments_json is not None
    assert json.loads(request.arguments_json) == arguments


def test_two_calls_that_differ_only_in_arguments_display_differently() -> None:
    """The attack ADR 0048 is named after, at the display layer: an operator
    reading these two must be able to tell them apart."""
    test = held({"dataset": "test"})
    production = held({"dataset": "production"})

    assert test.arguments_json != production.arguments_json


# ---------------------------------------------------------------------------
# The bound
# ---------------------------------------------------------------------------


def test_arguments_within_the_bound_are_kept() -> None:
    request = held({"blob": "x" * 64})

    assert request.arguments_json is not None


def test_arguments_over_the_bound_are_withheld_not_truncated() -> None:
    """Truncating would show a *different* call from the one being approved —
    the confusion this whole module exists to prevent, reintroduced in the one
    place a human is looking."""
    request = held({"blob": "x" * (MAX_DISPLAYED_ARGUMENT_BYTES + 1)})

    assert request.arguments_json is None


def test_a_withheld_call_still_reports_its_size() -> None:
    """ "Too large to show" and "how large" are different answers, and the second
    is the one that tells an operator whether to go and look elsewhere."""
    request = held({"blob": "x" * (MAX_DISPLAYED_ARGUMENT_BYTES + 1)})

    assert request.arguments_bytes > MAX_DISPLAYED_ARGUMENT_BYTES


def test_a_withheld_call_is_still_fingerprinted_over_everything() -> None:
    """**The security property survives the display limit.** What is withheld is
    the view, never the binding: a call too large to read is still bound to the
    exact arguments it was asked with, so an approval for it cannot be spent on
    a different one."""
    arguments = {"blob": "x" * (MAX_DISPLAYED_ARGUMENT_BYTES + 1)}
    request = held(arguments)

    assert request.fingerprint == fingerprint(
        subject=SUBJECT, actor=None, tool=TOOL, arguments=arguments
    )


def test_a_call_with_no_arguments_is_shown_as_having_none() -> None:
    """Distinct from withheld. ``{}`` means "this call took no arguments";
    ``None`` means "you are being asked to approve something you cannot see"."""
    request = held({})

    assert request.arguments_json == "{}"
    assert request.arguments_bytes == 2
