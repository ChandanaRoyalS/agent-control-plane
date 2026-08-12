"""The `input_required` result, and whether the token actually reaches a client.

**This file exists because of how the failure looks.** Pydantic ignores a key it
does not recognise rather than rejecting it, so a wrong field or alias produces a
perfectly valid `input_required` result with the `request_state` silently
missing — an approval the client can never answer, from a converter that
constructed without complaint.

Probing the installed SDK showed exactly that trap: a dict carrying
`requestState` was "accepted" by `CallToolResult` and the key was dropped on the
way through, because `request_state` is not a field there at all. So these
assertions are made against the **serialised** result, not the constructed one.
Construction proves nothing here; only what goes on the wire does.
"""

from __future__ import annotations

from acp.gateway.converters import APPROVAL_META_KEY, to_input_required, to_wire

TOKEN = "9nJc0Yv7Q2sWm4tR6bE1kL8pA3xZ5dGh"


def test_the_token_survives_serialisation() -> None:
    """**The assertion this module is for.** If this fails, the gateway is
    telling clients to wait and giving them nothing to wait with."""
    wire = to_wire(to_input_required(token=TOKEN, expires_in=300))

    assert TOKEN in str(wire), f"the request_state did not reach the wire: {wire}"


def test_the_result_says_input_required() -> None:
    wire = to_wire(to_input_required(token=TOKEN, expires_in=300))

    assert wire.get("resultType") == "input_required"


def test_no_input_requests_are_asked_of_the_client() -> None:
    """**A security decision, not an omission.**

    MRTR's `input_requests` asks the *client* to satisfy something — including an
    elicitation put to its user. Using one to ask "approve this delete?" is the
    obvious move and it is theatre: the client is the agent, and an agent talked
    into a destructive call by a poisoned document is exactly the one that will
    answer yes on its own behalf. A boundary the caller can satisfy is not a
    boundary.
    """
    result = to_input_required(token=TOKEN, expires_in=300)

    assert not result.input_requests


def test_the_notice_tells_the_caller_what_is_happening() -> None:
    """Enough to be useful to a model deciding what to tell its user, and
    nothing more."""
    wire = to_wire(to_input_required(token=TOKEN, expires_in=300))
    notice = str(wire)

    assert APPROVAL_META_KEY in notice
    assert "awaiting_human_approval" in notice


def test_the_notice_never_names_the_rule() -> None:
    """Which rule held a call is an oracle a caller can map one request at a
    time — the same reason `PolicyDeniedError` withholds it. The converter is
    not even given the rule, so there is nothing here to leak by accident."""
    wire = to_wire(to_input_required(token=TOKEN, expires_in=300))

    assert "rule" not in str(wire).lower()


def test_a_lapsed_window_reports_zero_rather_than_a_negative() -> None:
    """The hint is computed from a clock that has moved on. "-4 seconds
    remaining" is a number no client should have to interpret."""
    wire = to_wire(to_input_required(token=TOKEN, expires_in=-4.0))

    assert "expiresInSeconds': 0" in str(wire) or '"expiresInSeconds": 0' in str(wire)
