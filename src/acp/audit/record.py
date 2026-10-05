"""The audit record: a closed schema, identical in shape on every path.

Records carry argument names, never values (ADR 0045); the approval record differs because
it is short-lived and seen only by the approver (ADR 0049). Redaction
(`acp.observability.log.redact`) runs before hashing so the digest covers the bytes on disk.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

AUDIT_VERSION: Final = "acp-audit-v1"
"""Hashed into every link so a rule change never reinterprets an existing chain.

Separate from the approval-fingerprint and result-cache stamps so each evolves alone.
"""


class Category(StrEnum):
    """The four chained categories plus human approval decisions; a fixed set auditors can query."""

    AUTHORIZATION = "authorization"
    """A policy decision: allowed, denied, or held for a person."""

    CREDENTIAL = "credential"
    """A credential minted for one upstream, on behalf of one principal."""

    TOOL_CALL = "tool_call"
    """A call that actually reached an upstream, and what came back."""

    FIREWALL = "firewall"
    """A screening finding, and whether it withheld anything."""

    APPROVAL = "approval"
    """A human's decision, or the request that asked for one."""


class Outcome(StrEnum):
    """The shared outcome vocabulary; `HELD` marks a call waiting for a person."""

    ALLOWED = "allowed"
    DENIED = "denied"
    HELD = "held"
    FAILED = "failed"
    """The gateway tried and could not (upstream error, refused exchange); not a `DENIED`."""

    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One auditable fact; frozen so it cannot change after hashing."""

    category: Category
    event: str
    """The operational log's event name, e.g. `policy.denied`."""

    at: float
    """Wall-clock seconds from the caller; ordering comes from `seq`/`prev`, not this."""

    subject: str | None = None
    actor: str | None = None
    """Subject (who it is for) and actor (which agent) are both recorded (ADR 0015)."""

    tenant: str | None = None
    """Which tenant this happened in; an archived chain cannot be migrated to add it later."""

    tool: str | None = None
    upstream: str | None = None
    rule: str | None = None
    """The deciding policy rule; recorded here, never returned to the caller (ADR 0027)."""

    outcome: Outcome | None = None
    reason: str | None = None
    """Short human-readable reason from a fixed set per call site."""

    detail: Mapping[str, Any] = field(default_factory=dict)
    """Category-specific fields, e.g. `argument_names`, `audience`; every key is named in tests."""

    def as_dict(self) -> dict[str, Any]:
        """The record as written, keeping ``None`` fields so the key set is stable."""
        return {
            "category": str(self.category),
            "event": self.event,
            "at": self.at,
            "subject": self.subject,
            "actor": self.actor,
            "tenant": self.tenant,
            "tool": self.tool,
            "upstream": self.upstream,
            "rule": self.rule,
            "outcome": str(self.outcome) if self.outcome is not None else None,
            "reason": self.reason,
            "detail": dict(self.detail),
        }


def canonical(payload: Mapping[str, Any]) -> str:
    """The canonical JSON a link is hashed over: sorted keys, compact, strict, non-ASCII kept.

    Deliberately separate from the approval fingerprint's encoding so they can evolve apart.
    """
    # Strict (no `default=str`): the hash must match the strict JSON the sink writes;
    # unserialisable values are refused before chaining (`FileAuditSink.append`).
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


MAX_RECORDED_TOOL_CHARS: Final = 64
"""Longest tool name recorded verbatim; mirrors `acp.gateway.naming` to avoid the import."""


def recordable_tool(tool: str | None) -> str | None:
    """The tool name as recorded: verbatim if short and printable, else length and hash prefix.

    Tool names come from caller input, so this stops callers writing arbitrary text into the log.
    """
    if tool is None:
        return None
    if len(tool) <= MAX_RECORDED_TOOL_CHARS and tool.isprintable():
        return tool
    digest = hashlib.sha256(tool.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"<unrecognised tool name: {len(tool)} chars, sha256 {digest}>"
