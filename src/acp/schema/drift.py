"""Diffing an observed catalogue against the baseline into typed drift events.

Each kind needs a different response: a changed description is a security event (the rug
pull), a changed schema a correctness event, a new tool a policy gap, a removed tool a coming
outage. A tool whose description and schema both moved emits two events.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from acp.schema.fingerprint import fingerprint_tool, short
from acp.schema.snapshot import SchemaSnapshot

DESCRIPTION_FIELD = "description"
SCHEMA_FIELD = "inputSchema"


class DriftKind(StrEnum):
    """What sort of change was observed; a closed set, safe as a metric label."""

    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    DESCRIPTION_CHANGED = "description_changed"
    SCHEMA_CHANGED = "schema_changed"
    METADATA_CHANGED = "metadata_changed"
    """Another part of the definition moved, e.g. a title, ``outputSchema`` or annotations."""

    UPSTREAM_UNBASELINED = "upstream_unbaselined"
    """Configured and answering but never captured; nothing to drift from yet."""

    UPSTREAM_REMOVED = "upstream_removed"
    """In the baseline but no longer configured; one event, not one per tool."""


_PHRASING: dict[DriftKind, str] = {
    DriftKind.TOOL_ADDED: "new tool ({after})",
    DriftKind.TOOL_REMOVED: "tool no longer offered (was {before})",
    DriftKind.DESCRIPTION_CHANGED: "description changed ({before} -> {after})",
    DriftKind.SCHEMA_CHANGED: "inputSchema changed ({before} -> {after})",
    DriftKind.METADATA_CHANGED: "definition metadata changed ({before} -> {after})",
    DriftKind.UPSTREAM_UNBASELINED: "no baseline recorded; run `acp schemas capture`",
    DriftKind.UPSTREAM_REMOVED: "in the baseline but not configured",
}


@dataclass(frozen=True, slots=True)
class DriftEvent:
    """One difference, in terms an operator can act on."""

    upstream: str
    kind: DriftKind
    tool: str | None = None
    before: str | None = None
    """Short digest of the previous definition, where there was one."""
    after: str | None = None
    """Short digest of the current definition, where there is one."""

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Identity for de-duplication; includes ``after`` so a further change re-alerts."""
        return (self.upstream, self.tool or "", str(self.kind), self.after or "")

    def describe(self) -> str:
        """One line for a terminal or alert; an unphrased kind raises (see
        ``test_every_kind_describes_itself``).
        """
        subject = f"{self.upstream}__{self.tool}" if self.tool else self.upstream
        phrasing = _PHRASING[self.kind].format(before=self.before, after=self.after)
        return f"{subject}: {phrasing}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "upstream": self.upstream,
            "tool": self.tool,
            "kind": str(self.kind),
            "before": self.before,
            "after": self.after,
        }


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Every difference found, in a stable order."""

    events: tuple[DriftEvent, ...] = ()

    @property
    def has_drift(self) -> bool:
        return bool(self.events)

    @property
    def outstanding(self) -> int:
        return len(self.events)

    def counts(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for event in self.events:
            totals[str(event.kind)] = totals.get(str(event.kind), 0) + 1
        return totals

    def for_upstream(self, upstream: str) -> tuple[DriftEvent, ...]:
        return tuple(event for event in self.events if event.upstream == upstream)

    def as_dict(self) -> dict[str, Any]:
        return {
            "drift": self.has_drift,
            "events": [event.as_dict() for event in self.events],
            "counts": self.counts(),
        }


def diff(
    baseline: SchemaSnapshot | None,
    observed: SchemaSnapshot,
    *,
    known: Collection[str] | None = None,
) -> DriftReport:
    """Compare an observed catalogue against a baseline.

    Args:
        baseline: The committed snapshot, or ``None`` if there is none.
        observed: What was fetched.
        known: Configured upstream names, so a baselined upstream not yet probed is not
            reported removed. Defaults to the observed upstreams.
    """
    speak_for = set(known) if known is not None else set(observed.upstreams)
    base = baseline or SchemaSnapshot()
    events: list[DriftEvent] = []

    for upstream in sorted(observed.upstreams):
        recorded = base.tools_for(upstream)
        if recorded is None:
            events.append(DriftEvent(upstream=upstream, kind=DriftKind.UPSTREAM_UNBASELINED))
            continue
        events.extend(_diff_tools(upstream, recorded, observed.upstreams[upstream].tools))

    for upstream in sorted(base.upstreams):
        if upstream not in speak_for:
            events.append(DriftEvent(upstream=upstream, kind=DriftKind.UPSTREAM_REMOVED))

    return DriftReport(events=tuple(sorted(events, key=_ordering)))


def _ordering(event: DriftEvent) -> tuple[str, str, str]:
    """Stable sort key, so identical inputs give identical reports."""
    return (event.upstream, event.tool or "", str(event.kind))


def _diff_tools(
    upstream: str,
    recorded: Mapping[str, Mapping[str, Any]],
    current: Mapping[str, Mapping[str, Any]],
) -> list[DriftEvent]:
    events: list[DriftEvent] = []

    for name in sorted(set(current) - set(recorded)):
        events.append(
            DriftEvent(
                upstream=upstream,
                tool=name,
                kind=DriftKind.TOOL_ADDED,
                after=short(fingerprint_tool(current[name])),
            )
        )

    for name in sorted(set(recorded) - set(current)):
        events.append(
            DriftEvent(
                upstream=upstream,
                tool=name,
                kind=DriftKind.TOOL_REMOVED,
                before=short(fingerprint_tool(recorded[name])),
            )
        )

    for name in sorted(set(recorded) & set(current)):
        events.extend(_diff_one_tool(upstream, name, recorded[name], current[name]))

    return events


def _diff_one_tool(
    upstream: str,
    tool: str,
    recorded: Mapping[str, Any],
    current: Mapping[str, Any],
) -> list[DriftEvent]:
    """Classify what moved in one tool; changes in unknown fields report as metadata."""
    before = fingerprint_tool(recorded)
    after = fingerprint_tool(current)
    if before == after:
        return []

    events = [
        DriftEvent(
            upstream=upstream,
            tool=tool,
            kind=kind,
            before=short(fingerprint_tool({field: recorded.get(field)})),
            after=short(fingerprint_tool({field: current.get(field)})),
        )
        for field, kind in (
            (DESCRIPTION_FIELD, DriftKind.DESCRIPTION_CHANGED),
            (SCHEMA_FIELD, DriftKind.SCHEMA_CHANGED),
        )
        if recorded.get(field) != current.get(field)
    ]

    if _rest(recorded) != _rest(current):
        events.append(
            DriftEvent(
                upstream=upstream,
                tool=tool,
                kind=DriftKind.METADATA_CHANGED,
                before=short(before),
                after=short(after),
            )
        )
    return events


def _rest(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Everything outside the two facets that get their own event kind."""
    return {
        key: value
        for key, value in definition.items()
        if key not in (DESCRIPTION_FIELD, SCHEMA_FIELD)
    }
