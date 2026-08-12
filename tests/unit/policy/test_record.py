"""Reading decisions back out of the gateway's own log.

The log is an operational artifact — rotated, interleaved, occasionally
truncated mid-line — so most of what is asserted here is *not dying*. A
simulator that raises on line 40,000 has answered no question at all, and the
operator's fallback is grepping the file by hand.

The other half is that skipping is counted, not silent. "I read 12 of your
40,000 lines" and "I read all 40,000" are different answers to *is this policy
edit safe*, and a reader that cannot tell them apart reports "no changes" for a
log it failed to parse.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from acp.identity.principal import Actor, Principal
from acp.observability.log import JsonFormatter
from acp.policy.enforce import ALLOWED_EVENT, DENIED_EVENT, enforce_call
from acp.policy.record import RecordedDecision, parse_traffic
from acp.policy.schema import Effect, Policy, Rule


def record_line(**fields: Any) -> str:
    payload: dict[str, Any] = {
        "timestamp": "2026-08-12T00:00:00.000+00:00",
        "level": "INFO",
        "logger": "acp.policy.enforce",
        "event": ALLOWED_EVENT,
        "subject": "alice",
        "actor": None,
        "tool": "mock-a__search",
        "rule": "allow-search",
        "decision": "allow",
        "reason": "allowed by rule 'allow-search'",
        "argument_names": [],
    }
    payload.update(fields)
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_decision_is_read_back_whole() -> None:
    traffic = parse_traffic([record_line(actor="agent-a", argument_names=["doc_id"])])

    assert traffic.decisions == (
        RecordedDecision(
            subject="alice",
            actor="agent-a",
            tool="mock-a__search",
            allowed=True,
            rule="allow-search",
            argument_names=frozenset({"doc_id"}),
        ),
    )
    assert traffic.unreadable == 0


def test_a_denial_is_read_as_a_denial() -> None:
    traffic = parse_traffic([record_line(event=DENIED_EVENT, decision="deny", rule=None)])

    decision = traffic.decisions[0]
    assert not decision.allowed
    assert decision.rule is None
    assert decision.verdict == "deny"


def test_a_record_predating_argument_names_reads_as_unknown() -> None:
    """`None` and `frozenset()` are different claims — "I do not know which
    arguments were sent" against "I know none were" — and the simulator's
    precision depends on the difference. Collapsing them for convenience would
    silently make old records look like argument-free calls."""
    line = json.loads(record_line())
    del line["argument_names"]

    traffic = parse_traffic([json.dumps(line)])

    assert traffic.decisions[0].argument_names is None


# ---------------------------------------------------------------------------
# Everything else in the file
# ---------------------------------------------------------------------------


def test_other_events_are_counted_not_skipped_silently() -> None:
    """A gateway's log is mostly not authorization decisions. Those lines are
    not errors; they are the rest of the process doing its job."""
    traffic = parse_traffic(
        [record_line(), json.dumps({"event": "upstream.call", "upstream": "mock-a"})]
    )

    assert len(traffic.decisions) == 1
    assert traffic.other_events == 1
    assert traffic.unreadable == 0


def test_a_truncated_line_is_skipped_and_counted() -> None:
    """What a log rotation during a write leaves behind."""
    traffic = parse_traffic([record_line(), '{"event": "policy.allowed", "sub'])

    assert len(traffic.decisions) == 1
    assert traffic.unreadable == 1
    assert traffic.total == 2


def test_a_console_formatted_line_is_skipped() -> None:
    """Somebody ran the gateway with `ACP_LOG_FORMAT=console` and kept the
    output. Not JSON, not a crash."""
    traffic = parse_traffic(["12:00:00.000 INFO     acp.policy.enforce policy.allowed subject=a"])

    assert traffic.decisions == ()
    assert traffic.unreadable == 1


def test_blank_lines_are_not_errors() -> None:
    traffic = parse_traffic(["", "   ", record_line(), ""])

    assert len(traffic.decisions) == 1
    assert traffic.unreadable == 0


def test_json_that_is_not_an_object_is_skipped() -> None:
    traffic = parse_traffic(["[1, 2, 3]", '"a string"', "null"])

    assert traffic.decisions == ()
    assert traffic.unreadable == 3


# ---------------------------------------------------------------------------
# Fields of the wrong type
# ---------------------------------------------------------------------------


def test_a_decision_event_missing_a_field_is_unreadable_not_invented() -> None:
    """It claims to be a decision and is not one. Counting it as unreadable is
    the point — the alternative is a default that produces a confident answer
    about a call nobody made."""
    line = json.loads(record_line())
    del line["tool"]

    traffic = parse_traffic([json.dumps(line)])

    assert traffic.decisions == ()
    assert traffic.unreadable == 1


def test_a_tool_that_is_not_a_string_is_not_coerced() -> None:
    traffic = parse_traffic([record_line(tool=7)])

    assert traffic.decisions == ()
    assert traffic.unreadable == 1


def test_an_unknown_verdict_is_not_guessed() -> None:
    """Neither "allow" nor "deny". Reading it as a denial would be the safe
    guess for a firewall and the wrong one for a simulator, whose whole output
    is a comparison against what actually happened."""
    traffic = parse_traffic([record_line(decision="maybe")])

    assert traffic.decisions == ()
    assert traffic.unreadable == 1


def test_argument_names_of_the_wrong_shape_degrade_to_unknown() -> None:
    """Not unreadable — the decision itself is intact, and only the field that
    sharpens the simulation is missing. Throwing the record away over it would
    lose a call the report should mention."""
    traffic = parse_traffic([record_line(argument_names="doc_id")])

    assert len(traffic.decisions) == 1
    assert traffic.decisions[0].argument_names is None


# ---------------------------------------------------------------------------
# Against the real writer
# ---------------------------------------------------------------------------


def test_it_reads_what_enforce_call_actually_writes(caplog: pytest.LogCaptureFixture) -> None:
    """The test that matters, because everything above uses a fixture I wrote.

    A reader tested only against its own idea of the format agrees with itself.
    This drives the real `enforce_call`, renders the record through the real
    `JsonFormatter`, and reads that back — so a field renamed on either side
    fails here rather than in production.
    """
    policy = Policy(
        rules=(
            Rule(
                name="allow-search",
                effect=Effect.ALLOW,
                subjects=("alice",),
                tools=("mock-a__search",),
            ),
        )
    )
    principal = Principal(
        subject="alice", issuer="https://idp.test", actor=Actor(subject="agent-a")
    )

    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(policy, principal, "mock-a__search", {"doc_id": "public", "limit": 10})

    lines = [JsonFormatter().format(record) for record in caplog.records]
    traffic = parse_traffic(lines)

    assert traffic.unreadable == 0
    assert traffic.decisions == (
        RecordedDecision(
            subject="alice",
            actor="agent-a",
            tool="mock-a__search",
            allowed=True,
            rule="allow-search",
            argument_names=frozenset({"doc_id", "limit"}),
        ),
    )


def test_the_written_record_never_carries_an_argument_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The privacy claim, asserted rather than promised in a docstring.

    Argument names come from a tool's schema; values are the user's data. A
    `doc_id` is as likely to be a patient record as a public page, and writing
    it here would put the payload this gateway exists to control into a log a
    dozen people and three vendors can read.
    """
    policy = Policy(rules=(Rule(name="allow-all", effect=Effect.ALLOW),))
    principal = Principal(subject="alice", issuer="https://idp.test")
    secret = "patient-90210-diagnosis"

    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(policy, principal, "mock-a__read", {"doc_id": secret})

    rendered = JsonFormatter().format(caplog.records[0])
    assert secret not in rendered
    assert "doc_id" in rendered
