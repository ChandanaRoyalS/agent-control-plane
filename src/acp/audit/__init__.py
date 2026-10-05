"""Tamper-evident audit log: decisions, credential exchanges, tool calls and findings, hash-chained.

`record` is the closed schema, `chain` the pure linking and verify rule, `sink` the storage
and restart recovery, and `writer` the request-path seam where fail-closed is decided.
The chain detects edits, splices and reordering but not tail truncation or a wholesale
rewrite; `checkpoint` adds the external anchor that catches those.
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
