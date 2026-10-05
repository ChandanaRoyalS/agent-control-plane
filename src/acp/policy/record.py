"""Read authorization decisions back out of the gateway's own log.

Parses the JSON lines `enforce_call` writes (ADR 0007) as input to the policy
simulator. Lines are untrusted: a malformed or non-decision line is skipped and
counted, never raised, and the count is reported so a partial parse is visible.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from acp.policy.enforce import ALLOWED_EVENT, APPROVAL_EVENT, DENIED_EVENT
from acp.policy.evaluate import Verdict

DECISION_EVENTS = frozenset({ALLOWED_EVENT, DENIED_EVENT, APPROVAL_EVENT})
"""The event names `enforce_call` emits, imported so a rename cannot desync them."""


@dataclass(frozen=True, slots=True)
class RecordedDecision:
    """One authorization decision the gateway actually made.

    ``argument_names`` is ``None`` when unknown (older records), distinct from an empty
    set meaning none were sent; the simulator relies on the difference.
    """

    subject: str
    actor: str | None
    tool: str
    allowed: bool
    rule: str | None
    argument_names: frozenset[str] | None

    requires_approval: bool = False
    """Held for a human (ADR 0048); as in ``Decision``, never true alongside ``allowed``."""

    @property
    def verdict(self) -> Verdict:
        if self.requires_approval:
            return Verdict.APPROVAL
        return Verdict.ALLOW if self.allowed else Verdict.DENY

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
    """Lines that were not JSON or not a valid decision; other events are not counted here."""

    other_events: int

    @property
    def total(self) -> int:
        return len(self.decisions) + self.unreadable + self.other_events


def _decision_from(payload: dict[str, Any]) -> RecordedDecision | None:
    """Return a decision record, or ``None``; fields are type-checked, never coerced."""
    subject = payload.get("subject")
    tool = payload.get("tool")
    verdict = payload.get("decision")
    if not isinstance(subject, str) or not isinstance(tool, str):
        return None
    if verdict not in (Verdict.ALLOW, Verdict.DENY, Verdict.APPROVAL):
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
        allowed=verdict == Verdict.ALLOW,
        requires_approval=verdict == Verdict.APPROVAL,
        rule=rule,
        argument_names=names,
    )


def parse_traffic(lines: Iterable[str]) -> Traffic:
    """Read every decision in ``lines``, counting what could not be read.

    Takes lines rather than a path, so any source works and large logs stream.
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
