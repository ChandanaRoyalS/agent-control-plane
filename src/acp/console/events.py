"""What a watcher sees, and how much of it is a record.

The console is a view of the audit chain, not a second account (ADR 0056, ADR
0050): events reach a watcher only after their entry is durable, from
`AuditLog.arecord`, with the record's fields. Breaker state and spend are not in
the chain, so they are streamed marked `OBSERVED`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from acp.audit.record import AuditRecord

SSE_EVENT: Final = "trace"


class Source(StrEnum):
    """Whether what you are looking at is a record or a sighting."""

    RECORDED = "recorded"
    """In the hash chain, shown only after it was written; `acp audit verify` covers it."""

    OBSERVED = "observed"
    """Live only: not in the chain and not verifiable."""


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One line in the console.

    Uses the audit record's field set (ADR 0050), not a UI-specific shape.
    """

    source: Source
    category: str
    event: str
    at: float
    seq: int | None = None
    """The chain position of a `RECORDED` event; `None` for an `OBSERVED` one."""

    subject: str | None = None
    actor: str | None = None
    tenant: str | None = None
    tool: str | None = None
    upstream: str | None = None
    rule: str | None = None
    outcome: str | None = None
    reason: str | None = None
    detail: Mapping[str, Any] | None = None
    """`None` when empty, so the wire shape drops it."""

    def as_dict(self) -> dict[str, Any]:
        """The wire shape, with `None` fields omitted."""
        payload: dict[str, Any] = {
            "source": self.source.value,
            "category": self.category,
            "event": self.event,
            "at": self.at,
        }
        optional = {
            "seq": self.seq,
            "subject": self.subject,
            "actor": self.actor,
            "tenant": self.tenant,
            "tool": self.tool,
            "upstream": self.upstream,
            "rule": self.rule,
            "outcome": self.outcome,
            "reason": self.reason,
            "detail": self.detail,
        }
        payload.update({name: value for name, value in optional.items() if value is not None})
        return payload

    def as_sse(self) -> str:
        """One Server-Sent Events frame.

        `json.dumps` escapes newlines, so free text cannot break the single `data:` line.
        """
        return f"event: {SSE_EVENT}\ndata: {json.dumps(self.as_dict(), separators=(',', ':'))}\n\n"


def from_record(record: AuditRecord, seq: int | None = None) -> TraceEvent:
    """The chain's own record, as a line to watch.

    A translation, not a shared type, so console fields cannot change what an
    archived chain verifies to (`RECORD_VERSION`).
    """
    return TraceEvent(
        source=Source.RECORDED,
        category=str(record.category),
        event=record.event,
        at=record.at,
        seq=seq,
        subject=record.subject,
        actor=record.actor,
        tenant=record.tenant,
        tool=record.tool,
        upstream=record.upstream,
        rule=record.rule,
        outcome=str(record.outcome) if record.outcome is not None else None,
        reason=record.reason,
        # `AuditRecord.detail` defaults to an empty mapping.
        detail=dict(record.detail) or None,
    )


def _text(value: object) -> str | None:
    """A field as text, or ``None``; never the string `"None"`."""
    return None if value is None else str(value)


def from_entry(seq: int, record: Mapping[str, Any]) -> TraceEvent:
    """A chain entry, as a line to watch; the path the gateway uses.

    Built from `Entry.record`, the redacted mapping that was hashed, never from the
    unredacted `AuditRecord`. Read defensively: unknown fields are ignored.
    """
    return TraceEvent(
        source=Source.RECORDED,
        category=str(record.get("category", "")),
        event=str(record.get("event", "")),
        at=float(record.get("at", 0.0) or 0.0),
        seq=seq,
        subject=_text(record.get("subject")),
        actor=_text(record.get("actor")),
        tenant=_text(record.get("tenant")),
        tool=_text(record.get("tool")),
        upstream=_text(record.get("upstream")),
        rule=_text(record.get("rule")),
        outcome=_text(record.get("outcome")),
        reason=_text(record.get("reason")),
        detail=dict(record.get("detail") or {}) or None,
    )


def observed(
    category: str,
    event: str,
    at: float,
    *,
    upstream: str | None = None,
    subject: str | None = None,
    tenant: str | None = None,
    detail: Mapping[str, Any] | None = None,
) -> TraceEvent:
    """Something worth watching that the chain does not record.

    Breaker transitions and running spend; this constructor always marks them
    `OBSERVED`.
    """
    return TraceEvent(
        source=Source.OBSERVED,
        category=category,
        event=event,
        at=at,
        upstream=upstream,
        subject=subject,
        tenant=tenant,
        detail=detail,
    )
