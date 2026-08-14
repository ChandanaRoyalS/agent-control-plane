"""What reaches the browser, and whether it claims to be a record — task 63.

The distinction between `RECORDED` and `OBSERVED` is the one thing in this
module a bug could make dishonest, so most of these are about that.
"""

from __future__ import annotations

import json

import pytest

from acp.audit.record import AuditRecord, Category, Outcome
from acp.console.events import SSE_EVENT, Source, from_record, observed


def a_record(**overrides: object) -> AuditRecord:
    fields: dict[str, object] = {
        "category": Category.AUTHORIZATION,
        "event": "policy.denied",
        "at": 1.5,
        "subject": "alice",
        "actor": "agent-7",
        "tenant": "acme",
        "tool": "mock-a__search",
        "rule": "deny-writes",
        "outcome": Outcome.DENIED,
        "reason": "no rule permits it",
    }
    fields.update(overrides)
    return AuditRecord(**fields)  # type: ignore[arg-type]


def test_a_chain_record_becomes_a_recorded_event() -> None:
    """The console shows it *because* it was written. Anything else would let a
    watcher see a call the chain does not have."""
    event = from_record(a_record(), seq=12)
    assert event.source is Source.RECORDED
    assert event.seq == 12


def test_every_field_the_auditor_needs_survives_the_translation() -> None:
    """The field set is the record's on purpose. A console field the chain
    cannot fill invites a question the chain cannot answer."""
    event = from_record(a_record())
    assert event.subject == "alice"
    assert event.actor == "agent-7"
    assert event.tenant == "acme"
    assert event.tool == "mock-a__search"
    assert event.rule == "deny-writes"
    assert event.outcome == "denied"
    assert event.reason == "no rule permits it"


def test_an_empty_detail_does_not_reach_the_wire() -> None:
    """`AuditRecord.detail` defaults to `{}`, and a `"detail":{}` on every line
    of a stream somebody is watching is bandwidth spent on nothing."""
    assert from_record(a_record()).detail is None
    assert "detail" not in from_record(a_record()).as_dict()


def test_a_real_detail_does() -> None:
    event = from_record(a_record(detail={"findings": 2}))
    assert event.as_dict()["detail"] == {"findings": 2}


def test_an_observed_event_is_marked_and_has_no_chain_position() -> None:
    """THE HONEST BIT. Breaker state and spend are not in the chain, and a
    viewer has to be able to tell what will still exist tomorrow.

    `seq` is `None` rather than 0, because 0 is a position and this has none."""
    event = observed("upstream", "breaker.open", 2.0, upstream="mock-a")
    assert event.source is Source.OBSERVED
    assert event.seq is None
    assert event.as_dict()["source"] == "observed"


def test_the_two_sources_are_distinguishable_on_the_wire() -> None:
    """If they were not, the page could not render them differently and the
    distinction would exist only in this file's docstring."""
    recorded = from_record(a_record()).as_dict()["source"]
    live = observed("upstream", "breaker.open", 2.0).as_dict()["source"]
    assert recorded != live


def test_the_sse_frame_names_its_event_and_ends_with_a_blank_line() -> None:
    """SSE terminates a frame on a blank line. A frame without one is never
    dispatched and the console silently shows nothing at all."""
    frame = from_record(a_record()).as_sse()
    assert frame.startswith(f"event: {SSE_EVENT}\ndata: ")
    assert frame.endswith("\n\n")


def test_the_payload_is_one_line_even_when_the_text_is_not() -> None:
    """THE ONE THAT WOULD BITE IN PRODUCTION. `reason` and `detail` carry free
    text from upstreams and detectors. A newline inside the payload ends the
    frame early, and the remainder is parsed as a nameless event — so a hostile
    document could truncate the very line reporting it."""
    frame = from_record(a_record(reason="line one\nline two")).as_sse()
    body = frame.removeprefix(f"event: {SSE_EVENT}\ndata: ").removesuffix("\n\n")
    assert "\n" not in body
    assert json.loads(body)["reason"] == "line one\nline two"


def test_a_carriage_return_is_escaped_too() -> None:
    """SSE treats CR, LF and CRLF alike as line terminators, so escaping only
    `\\n` would leave the same hole open one character over."""
    frame = from_record(a_record(reason="one\r\ntwo")).as_sse()
    body = frame.removeprefix(f"event: {SSE_EVENT}\ndata: ").removesuffix("\n\n")
    assert "\r" not in body
    assert json.loads(body)["reason"] == "one\r\ntwo"


def test_an_event_is_frozen() -> None:
    """It is handed to every watcher. One of them mutating it would change what
    the others see, after the fact."""
    event = from_record(a_record())
    with pytest.raises(AttributeError):
        event.subject = "bob"  # type: ignore[misc]
