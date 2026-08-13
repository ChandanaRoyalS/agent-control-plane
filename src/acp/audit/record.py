"""What an audit record is, and what it deliberately is not.

Task 56. The plan asks for "every authorization decision, credential exchange,
tool call and firewall finding, chained", and the chaining is the easy half. The
hard half is deciding what a record *contains*, because an audit log is the one
artifact in this project that outlives every argument about it.

**A closed schema, not a bag of fields.** The operational log takes whatever
``extra=`` a call site felt like passing; that is right for a log and wrong here.
An auditor's questions — *what did this agent do, who was it acting for, what
stopped it* — can only be answered by a record whose shape is the same on every
path. Two call sites emitting near-identical dictionaries is how a field appears
on one and not the other, and a record whose shape depends on the outcome is one
no query can group by.

**Argument names, never argument values.** The same rule the decision log follows
(ADR 0045), and the *opposite* of what the approval record does (ADR 0049) — which
looks like an inconsistency and is not one. The axis is exposure, not data. This
file is durable, rotated, archived and read by everyone with log access; an
approval record lives five minutes in memory in front of the one person deciding.
Same values, different readers, different answers.

**Redaction happens before the hash is taken**, in `acp.observability.log.redact`,
so the digest covers exactly the bytes on disk. Hashing first would produce a
chain that cannot be verified against the file it describes — the failure mode
would be a verifier that reports tampering on a file nobody touched, which is
worse than no verifier at all.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

AUDIT_VERSION: Final = "acp-audit-v1"
"""Stamped into every link, so what "the same record" means can change without
an existing chain being reinterpreted under the new rule.

The same discipline as the approval fingerprint and the result-cache key, and
deliberately a *third* stamp rather than a shared one: a change made for one
carries no implication for the others, and this is the one where a silent
reinterpretation would mean an archived chain quietly failing to verify.
"""


class Category(StrEnum):
    """The four things the plan names, plus the one task 55 added.

    A category rather than a free string, because "show me every authorization
    decision for this subject" is the query an auditor actually types, and it
    cannot be typed against a field whose values were chosen ad hoc at eleven
    call sites.
    """

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
    """What happened, in the only vocabulary the whole log shares.

    Five values, and the important one is `HELD`. A call waiting for a person is
    neither permitted nor refused, and recording it as either would make the
    approval flow invisible in the record that is supposed to explain what
    happened — the same argument `Decision.requires_approval` makes in the
    policy engine, carried into the artifact an auditor reads.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    HELD = "held"
    FAILED = "failed"
    """The gateway tried and could not — an upstream error, an exchange refused.
    Distinct from `DENIED`, which is a decision this gateway made on purpose."""

    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One auditable fact, in the shape every one of them shares.

    Frozen, because a record that can be edited after it is hashed is a record
    whose hash means nothing. `slots` for the same reason it is used elsewhere
    here: a typo'd attribute should be an error rather than a silently ignored
    assignment on an object somebody is about to write to disk.
    """

    category: Category
    event: str
    """The event name the operational log already uses — `policy.denied`,
    `auth.exchanged`. Shared on purpose: an operator reading a log line and an
    auditor reading the chain should be naming the same thing, and a second
    vocabulary is a translation table somebody has to maintain."""

    at: float
    """Wall-clock seconds, injected by the caller rather than read here.

    Not part of the chain's integrity claim — a clock can be wrong, and a record
    is bound to its position by `seq` and `prev`, not by its timestamp. It is
    recorded because "when" is the first question anybody asks, and it is
    *ordered* by the chain rather than by itself.
    """

    subject: str | None = None
    actor: str | None = None
    """Both identities, always. This project's whole authorization model is that
    "who is this for" and "which agent did it" are different questions
    (ADR 0015), so a record carrying only the human leaves *which of the four
    agents acting for alice did this* unanswerable — the question that matters
    precisely when one of them is misbehaving."""

    tenant: str | None = None
    """Which tenant this happened in (task 58).

    Present from the first version deliberately. Adding it later means every
    record written before the change is ambiguous rather than merely
    tenant-less, and an archived chain cannot be migrated — rewriting it is
    exactly what the chain exists to detect.
    """

    tool: str | None = None
    upstream: str | None = None
    rule: str | None = None
    """The policy rule that decided, when one did. Written here and **never** to
    the caller — the log gets the rule, the caller gets an undifferentiated
    refusal (ADR 0027)."""

    outcome: Outcome | None = None
    reason: str | None = None
    """Short, from a fixed set at each call site, for the human reading a row."""

    detail: Mapping[str, Any] = field(default_factory=dict)
    """Category-specific fields with defined meanings — `argument_names`,
    `finding_families`, `audience`, `expires_in`.

    A mapping rather than more columns, because the alternative is a dataclass
    with forty optional fields of which each record sets four. It is **not** a
    free-for-all: every key that appears here is named in this module's tests, so
    a new one is a deliberate act rather than something a call site invents.
    """

    def as_dict(self) -> dict[str, Any]:
        """The record as it goes on the wire, with nothing absent-but-implied.

        ``None`` fields are **kept**, not dropped. A dropped field and a field
        that was genuinely unknown are the same bytes to a verifier and very
        different facts to an auditor — and, more practically, a record whose key
        set depends on which fields happened to be set is one that cannot be
        canonicalised stably as the schema grows.
        """
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
    """The one encoding a link is computed over.

    Keys sorted, no insignificant whitespace, `ensure_ascii=False` so a tool
    named in a language that is not English hashes as itself rather than as its
    escape sequence. `allow_nan=False` because `NaN` is not JSON and a verifier
    written in any other language would reject the line this process happily
    wrote.

    **Not shared with the approval fingerprint**, though the code would be
    identical today. Same shape, different failure directions: a change made
    there for a reason about approvals must not silently reinterpret an archive.
    They carry separate version stamps and are allowed to evolve apart.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )
