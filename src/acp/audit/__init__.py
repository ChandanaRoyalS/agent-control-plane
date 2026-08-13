"""Tamper-evident audit: what happened, in an order nobody can quietly edit.

Task 56. Every authorization decision, credential exchange, tool call and
firewall finding, chained — each entry carrying the hash of the one before it, so
changing any record invalidates every link after it.

**The four modules, and why they are four.**

- `record` — what an auditable fact *is*. A closed schema, not a bag of fields.
- `chain` — the linking rule, and an honest account of what it does and does not
  prove. Pure: no filesystem, no clock, no gateway.
- `sink` — where entries land, how a restart continues the chain rather than
  starting a second one, and why a tail it cannot read stops the process.
- `writer` — the seam the request path calls, and the single place fail-closed
  is decided.

Kept apart so the linking rule is testable by hashing a list of dictionaries,
and so a Postgres- or object-store-backed sink arrives later as a class rather
than a redesign.

**The claim, stated exactly.** A hash chain detects modification, splicing and
reordering. It does **not** detect truncation of the tail — a shorter valid chain
is still a valid chain — nor a wholesale rewrite by somebody who owns the
storage. Those are answered by `checkpoint`: an anchor small enough to live
somewhere the writer cannot reach, compared against on every verification. *A
chain plus an external anchor is tamper-evident; a chain alone is tamper-evident
to anybody who already knows where it should end.*
"""

from acp.audit.chain import GENESIS, Break, Chain, Entry, Verification, link, verify
from acp.audit.checkpoint import (
    DEFAULT_CHECKPOINT_PATH,
    Anchoring,
    Checkpoint,
    check,
)
from acp.audit.checkpoint import load as load_checkpoint
from acp.audit.record import AUDIT_VERSION, AuditRecord, Category, Outcome, canonical
from acp.audit.sink import AuditSink, FileAuditSink, MemoryAuditSink, recover
from acp.audit.writer import FAILURE_EVENT, AuditLog

__all__ = [
    "AUDIT_VERSION",
    "DEFAULT_CHECKPOINT_PATH",
    "FAILURE_EVENT",
    "GENESIS",
    "Anchoring",
    "AuditLog",
    "AuditRecord",
    "AuditSink",
    "Break",
    "Category",
    "Chain",
    "Checkpoint",
    "Entry",
    "FileAuditSink",
    "MemoryAuditSink",
    "Outcome",
    "Verification",
    "canonical",
    "check",
    "link",
    "load_checkpoint",
    "recover",
    "verify",
]
