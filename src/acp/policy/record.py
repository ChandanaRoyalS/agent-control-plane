"""Read authorization decisions back out of the gateway's own log.

`enforce_call` writes one JSON object per decision (ADR 0007's shape: an event
name plus fields). This reads them back, and it is the input to the policy
simulator — the recorded traffic a proposed policy is replayed against.

**The log is an operational artifact, not a data file this module owns.** It is
written by a running gateway, rotated by something else, interleaved with every
other event the process emits, and quite possibly truncated in the middle of a
line by whatever was copying it when the disk filled. So every line is treated
as untrusted: a line that does not parse, or parses into something that is not a
decision, is *skipped and counted*, never an exception. A simulator that dies on
line 40,000 of a log has answered no question at all, and the operator's next
move — `grep` the file by hand — is strictly worse than the answer it could have
given about the other 39,999.

The count is reported rather than swallowed, because "I read 12 of your 40,000
lines" and "I read all 40,000" are very different answers to *is this policy
edit safe*, and a simulator that cannot tell them apart is one that quietly
reports "no changes" for a log it failed to parse.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from acp.policy.enforce import ALLOWED_EVENT, DENIED_EVENT

DECISION_EVENTS = frozenset({ALLOWED_EVENT, DENIED_EVENT})
"""The two event names `enforce_call` emits, imported rather than spelled again.

A reader with its own copy of these strings is a reader that silently stops
finding anything the day somebody renames the event.
"""


@dataclass(frozen=True, slots=True)
class RecordedDecision:
    """One authorization decision the gateway actually made.

    Carries what the log carries and nothing invented. In particular
    ``argument_names`` is ``None`` when the record predates the field, which is
    a *different* claim from ``frozenset()`` — "I do not know which arguments
    were sent" versus "I know none were". The simulator's precision depends on
    the difference, so it is not collapsed into an empty set for convenience.
    """

    subject: str
    actor: str | None
    tool: str
    allowed: bool
    rule: str | None
    argument_names: frozenset[str] | None

    @property
    def verdict(self) -> str:
        return "allow" if self.allowed else "deny"

    def describe(self) -> str:
        """One line naming the call, for a report a human reads."""
        who = f"{self.subject}+{self.actor}" if self.actor else self.subject
        args = ""
        if self.argument_names:
            args = f" ({', '.join(sorted(self.argument_names))})"
        return f"{who} -> {self.tool}{args}"


@dataclass(frozen=True, slots=True)
class Traffic:
    """Everything readable in one log, and an honest count of what was not."""

    decisions: tuple[RecordedDecision, ...]
    unreadable: int
    """Lines that were not JSON, or were JSON of the wrong shape.

    Not lines that were simply other events — those are not errors, they are
    the rest of the gateway doing its job in the same file.
    """

    other_events: int

    @property
    def total(self) -> int:
        return len(self.decisions) + self.unreadable + self.other_events


def _decision_from(payload: dict[str, Any]) -> RecordedDecision | None:
    """A decision record, or ``None`` if this object is not one.

    Every field is checked for the type it must have rather than coerced. A
    record whose ``tool`` arrived as a number is not a tool call this simulator
    can reason about, and turning it into the string ``"7"`` would produce a
    confident answer about a call that never happened.
    """
    subject = payload.get("subject")
    tool = payload.get("tool")
    verdict = payload.get("decision")
    if not isinstance(subject, str) or not isinstance(tool, str):
        return None
    if verdict not in ("allow", "deny"):
        return None

    actor = payload.get("actor")
    if actor is not None and not isinstance(actor, str):
        return None
    rule = payload.get("rule")
    if rule is not None and not isinstance(rule, str):
        return None

    names: frozenset[str] | None = None
    raw_names = payload.get("argument_names")
    if isinstance(raw_names, list) and all(isinstance(name, str) for name in raw_names):
        names = frozenset(raw_names)

    return RecordedDecision(
        subject=subject,
        actor=actor,
        tool=tool,
        allowed=verdict == "allow",
        rule=rule,
        argument_names=names,
    )


def parse_traffic(lines: Iterable[str]) -> Traffic:
    """Read every decision in ``lines``, counting what could not be read.

    Takes an iterable of lines rather than a path so the caller decides where
    the log comes from — a file, a pipe, a test's list of strings — and so a
    log larger than memory streams rather than loads. The gateway's own log is
    the expected source; nothing here assumes it.
    """
    decisions: list[RecordedDecision] = []
    unreadable = 0
    other = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            # A half-written line from a rotation, a console-formatted line, or
            # something else entirely. One bad line is not a reason to stop.
            unreadable += 1
            continue
        if not isinstance(payload, dict):
            unreadable += 1
            continue
        if payload.get("event") not in DECISION_EVENTS:
            other += 1
            continue
        decision = _decision_from(payload)
        if decision is None:
            unreadable += 1
            continue
        decisions.append(decision)

    return Traffic(decisions=tuple(decisions), unreadable=unreadable, other_events=other)
