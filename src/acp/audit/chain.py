"""The hash chain: each entry carries the previous entry's hash, plus `verify`.

Detects modification, splicing and reordering. It cannot detect tail truncation or a
wholesale rewrite by someone who owns the storage; `acp.audit.checkpoint` anchors the head
outside the writer's reach for that (same shape as ADR 0013). Sequence numbers are hashed
too, so a break names its entry and cannot be renumbered away.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from acp.audit.record import AUDIT_VERSION, AuditRecord, canonical

if TYPE_CHECKING:
    from acp.audit.signing import Signer, Verifier

GENESIS: Final = "0" * 64
"""The `prev` of the first entry, explicit so the first entry is checked like any other."""

SEQ_START: Final = 1
"""Entries are numbered from one, so the last `seq` is the entry count."""


def link(*, prev: str, seq: int, payload: Mapping[str, Any]) -> str:
    """SHA-256 binding this record to the one before it.

    Hashes a canonical JSON structure (not concatenated strings, which are ambiguous) and
    includes the audit version, so a chain cannot verify under a different rule.
    """
    material = canonical(
        {"v": AUDIT_VERSION, "prev": prev, "seq": seq, "record": canonical(payload)}
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Entry:
    """One record, with its position and its binding."""

    seq: int
    prev: str
    hash: str
    record: Mapping[str, Any]
    """The redacted record as a plain mapping.

    Kept unparsed so fields from a newer writer are still hashed during verification.
    """

    sig: str | None = None
    """Ed25519 signature over `hash` (ADR 0078); absent on an unsigned chain."""

    kid: str | None = None
    """Which key signed it."""

    def as_dict(self) -> dict[str, Any]:
        out = {"seq": self.seq, "prev": self.prev, "hash": self.hash, "record": dict(self.record)}
        if self.sig is not None:
            out["sig"] = self.sig
            out["kid"] = self.kid
        return out

    @property
    def valid(self) -> bool:
        """Whether this entry's own hash matches its contents and position."""
        return self.hash == link(prev=self.prev, seq=self.seq, payload=self.record)


def next_entry(
    *, head: str, seq: int, payload: Mapping[str, Any], signer: Signer | None = None
) -> Entry:
    """The entry that follows ``head``, signed when a signer is given."""
    digest = link(prev=head, seq=seq, payload=payload)
    if signer is None:
        return Entry(seq=seq, prev=head, hash=digest, record=payload)
    return Entry(
        seq=seq, prev=head, hash=digest, record=payload, sig=signer.sign(digest), kid=signer.kid
    )


class Chain:
    """The in-process head of a chain; produces entries, while `acp.audit.sink` stores them."""

    def __init__(
        self, head: str = GENESIS, seq: int = SEQ_START - 1, *, signer: Signer | None = None
    ) -> None:
        self._head = head
        self._seq = seq
        self._signer = signer

    @property
    def head(self) -> str:
        return self._head

    @property
    def length(self) -> int:
        return self._seq

    def append(self, record: AuditRecord | Mapping[str, Any]) -> Entry:
        """Extend the chain by one, advancing the head."""
        payload = record.as_dict() if isinstance(record, AuditRecord) else dict(record)
        entry = next_entry(head=self._head, seq=self._seq + 1, payload=payload, signer=self._signer)
        self._head = entry.hash
        self._seq = entry.seq
        return entry


# ---------------------------------------------------------------------------
# Verification (behind `acp audit verify`)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Break:
    """One broken link: its sequence number (if readable), file line and reason."""

    seq: int | None
    line: int
    reason: str

    def describe(self) -> str:
        at = f"entry {self.seq}" if self.seq is not None else "an unnumbered entry"
        return f"line {self.line}: {at} — {self.reason}"


@dataclass(frozen=True, slots=True)
class Verification:
    """The result of walking a chain, whole."""

    entries: int
    head: str
    breaks: tuple[Break, ...]
    unreadable: int
    """Lines that were not JSON or not an entry; any makes the chain not intact."""

    anchor_hash: str | None = None
    """Hash of the entry at `anchor_seq`, captured during the walk so memory stays O(1)."""

    signed: int = 0
    """Entries carrying a signature, checked or not."""

    signatures_checked: bool = False
    """Whether a verifier was given, so every entry's signature was required and checked."""

    @property
    def intact(self) -> bool:
        return not self.breaks and not self.unreadable

    def describe(self) -> str:
        if self.intact:
            signatures = (
                f", all {self.entries} signatures valid"
                if self.signatures_checked
                else f", {self.signed} signed (not checked: no public key given)"
                if self.signed
                else ""
            )
            return f"{self.entries} entries, chain intact{signatures}, head {self.head[:16]}…"
        lines = [f"{self.entries} entries read, {len(self.breaks)} break(s)"]
        if self.unreadable:
            lines.append(f"{self.unreadable} unreadable line(s)")
        lines.extend(f"  {b.describe()}" for b in self.breaks)
        return "\n".join(lines)


def _entry_from(payload: object) -> Entry | None:
    """An entry, or ``None`` if any field has the wrong type (no coercion)."""
    if not isinstance(payload, dict):
        return None
    seq, prev, digest, record = (
        payload.get("seq"),
        payload.get("prev"),
        payload.get("hash"),
        payload.get("record"),
    )
    if not isinstance(seq, int) or isinstance(seq, bool):
        return None
    if not isinstance(prev, str) or not isinstance(digest, str):
        return None
    if not isinstance(record, dict):
        return None
    sig, kid = payload.get("sig"), payload.get("kid")
    unsigned = sig is None and kid is None
    if not (unsigned or (isinstance(sig, str) and isinstance(kid, str))):
        return None
    return Entry(seq=seq, prev=prev, hash=digest, record=record, sig=sig, kid=kid)


def _signature_problem(entry: Entry, verifier: Verifier, file_kid: str | None) -> str | None:
    """Why this entry's signature is not acceptable, or ``None``: valid, and by the file's key."""
    problem = verifier.problem(entry.hash, entry.sig, entry.kid)
    if problem is None and file_kid is not None and entry.kid != file_kid:
        problem = f"signed by key {entry.kid}, but this file's entries use {file_kid}"
    return problem


def verify(
    lines: Iterable[str],
    *,
    expected_head: str = GENESIS,
    anchor_seq: int | None = None,
    verifier: Verifier | None = None,
) -> Verification:
    """Stream a chain's lines and report every break, not just the first.

    With a ``verifier``, every entry must be signed by one of its keys, and all by the
    same key: one key signs one file (ADR 0078).
    """
    import json  # noqa: PLC0415 — local, so this module's import graph stays hash-only

    breaks: list[Break] = []
    unreadable = 0
    head = expected_head
    seq = SEQ_START - 1
    count = 0
    anchor_hash: str | None = None
    signed = 0
    file_kid: str | None = None

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            unreadable += 1
            breaks.append(Break(seq=None, line=number, reason="not JSON"))
            continue

        entry = _entry_from(parsed)
        if entry is None:
            unreadable += 1
            breaks.append(Break(seq=None, line=number, reason="not an audit entry"))
            continue

        count += 1
        if entry.seq != seq + 1:
            breaks.append(Break(entry.seq, number, f"sequence jumped from {seq} to {entry.seq}"))
        if entry.prev != head:
            breaks.append(Break(entry.seq, number, "prev does not match the previous entry's hash"))
        if not entry.valid:
            breaks.append(Break(entry.seq, number, "hash does not match this entry's contents"))

        if entry.sig is not None:
            signed += 1
        if verifier is not None:
            problem = _signature_problem(entry, verifier, file_kid)
            if problem is not None:
                breaks.append(Break(entry.seq, number, problem))
            elif file_kid is None:
                file_kid = entry.kid

        if anchor_seq is not None and entry.seq == anchor_seq:
            anchor_hash = entry.hash

        # Continue from the file's claimed hash so one edit reports one break, not a cascade.
        head = entry.hash
        seq = entry.seq

    return Verification(
        entries=count,
        head=head,
        breaks=tuple(breaks),
        unreadable=unreadable,
        anchor_hash=anchor_hash,
        signed=signed,
        signatures_checked=verifier is not None,
    )
