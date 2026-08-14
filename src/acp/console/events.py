"""What a watcher sees, and how much of it is a record.

Task 63: *"Server-sent events streaming tool calls, denials, firewall findings,
breaker state and spend. Minimal styling, no framework ceremony — it exists to
be watched for thirty seconds."*

**The console is a view of the audit chain, not a second telemetry path.**

That is the decision this module exists to express, and the alternative was
tempting: an event bus the request path publishes to directly, carrying whatever
shape each call site found convenient. It would have been less code and it would
have created a second account of what happened.

Two accounts of the same events is a question nobody wants to answer at 3am:
*the console showed the call and the chain does not — which one is wrong?* This
gateway's central claim is that a call it cannot record does not happen
(ADR 0050). A live view that can disagree with the record quietly weakens that
claim, because it gives an operator a second place to look and no way to rank
them.

So events reach a watcher **after** their entry is durable, out of the same
`AuditLog.arecord` that wrote it, carrying the fields the record carries.

**But two of the five things the plan asks for are not in the chain**, and
pretending otherwise would be the more comfortable lie:

- **breaker state** is an upstream's health changing, which the gateway logs and
  does not audit — no principal asked for it and no decision was made about a
  call
- **spend** is a running total, not an event; the chain records the calls a total
  could be computed from, and never the total

They are worth watching anyway — a demo where an upstream trips its breaker and
the console says so is the demo — so they are streamed, and marked. `Source`
carries that distinction to the browser, and the page renders it, because **a
viewer has to be able to tell what will still exist tomorrow.**
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
    """It is in the hash chain. It survives a restart, `acp audit verify` covers
    it, and the console showed it *because* it was written — not before."""

    OBSERVED = "observed"
    """Live only. True when it was emitted and gone when this process is. Not in
    the chain, not verifiable, and not evidence of anything tomorrow."""


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One line in the console.

    Deliberately the audit record's field set rather than a shape chosen for the
    UI. A console field the record cannot fill is a console that invites
    questions the chain cannot answer, and the fields here were already chosen
    for the auditor's questions (ADR 0050) — who it was for, which agent did it,
    which rule decided.
    """

    source: Source
    category: str
    event: str
    at: float
    seq: int | None = None
    """The chain position, for a `RECORDED` event. `None` for an `OBSERVED` one,
    and that absence is the honest rendering of "this has no position in
    anything" rather than a zero that looks like the beginning."""

    subject: str | None = None
    actor: str | None = None
    tenant: str | None = None
    tool: str | None = None
    upstream: str | None = None
    rule: str | None = None
    outcome: str | None = None
    reason: str | None = None
    detail: Mapping[str, Any] | None = None
    """`None` rather than the record's empty-dict default, because the wire
    shape drops empty fields and `{}` is not information a watcher needs."""

    def as_dict(self) -> dict[str, Any]:
        """The wire shape, with empty fields dropped.

        Dropped rather than sent as `null`: most events fill a handful of these,
        and a browser holding a stream open for a demo should not spend its
        bandwidth on eleven nulls per line.
        """
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

        `json.dumps` with no newlines in the output is what makes a single
        `data:` line correct — SSE terminates a frame on a blank line, so a
        payload containing one would truncate the event and leave the rest of it
        parsed as a new frame with no name. The audit record's `reason` and
        `detail` are free text from upstreams and detectors, so this is not a
        theoretical concern.
        """
        return f"event: {SSE_EVENT}\ndata: {json.dumps(self.as_dict(), separators=(',', ':'))}\n\n"


def from_record(record: AuditRecord, seq: int | None = None) -> TraceEvent:
    """The chain's own record, as a line to watch.

    A translation rather than a shared type, and the seam is deliberate: the
    audit record is hashed and its field set is a compatibility surface
    (`RECORD_VERSION`), while this one is a rendering. Adding a field here must
    not be able to change what an archived chain verifies to.
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
        # `or None` because `AuditRecord.detail` defaults to an empty mapping
        # rather than to `None`, and an empty one carries nothing worth a line
        # of JSON on a stream somebody is watching.
        detail=dict(record.detail) or None,
    )


def _text(value: object) -> str | None:
    """A field as text, or nothing. Never a stringified `None`.

    `str(None)` is `"None"`, which renders in a browser as a four-letter word
    in the subject column and looks exactly like a principal.
    """
    return None if value is None else str(value)


def from_entry(seq: int, record: Mapping[str, Any]) -> TraceEvent:
    """A chain entry, as a line to watch. **The path the gateway uses.**

    Built from `Entry.record` — the mapping that was hashed and written — rather
    than from the `AuditRecord` that produced it, and that is a security
    property rather than a convenience. **Redaction runs before the entry is
    chained**, so the mapping is the redacted one and the object is not. A
    console rendering the object would put on screen exactly the fields
    redaction exists to keep off disk, to an operator who reasonably assumes
    they are looking at the record.

    Read defensively for the same reason `Entry.record` is a mapping at all: it
    may have been written by a newer version of this code carrying fields this
    one does not know about. A console is not the place to be strict about that
    — it should show what it understands and not fail on the rest.
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

    Breaker transitions and running spend. Constructed through a named function
    rather than by building a `TraceEvent` at the call site, so that **marking it
    `OBSERVED` is not a thing anybody can forget** — the failure mode being
    guarded against is a live-only event reaching the browser labelled as part
    of the record.
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
