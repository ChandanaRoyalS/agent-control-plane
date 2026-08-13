"""The chain itself: what each link proves, and the one thing it cannot.

Task 56. Every entry carries the hash of the entry before it, so changing any
record invalidates every link after it. That is the whole mechanism, and it is
worth being precise about what it buys, because "tamper-evident" is a word people
use much more loosely than it deserves.

**What a hash chain detects**

- **Modification.** Edit a record and its hash no longer matches; edit its hash
  to match and the next entry's `prev` no longer matches. Fixing that means
  recomputing every link to the end.
- **Splicing.** Insert or remove an entry in the middle and the `prev` of the
  following one is wrong.
- **Reordering.** Two entries swapped are two broken links.

**What it does not detect, and this is the honest part**

- **Truncation of the tail.** Delete the last thousand entries and what remains
  is a *perfectly valid chain*. Nothing inside the file can say otherwise,
  because the file no longer contains the evidence. This is not a flaw in the
  implementation; it is what a self-contained log can be.
- **A wholesale rewrite.** An attacker who can write the file and knows the
  scheme can rebuild the entire chain from genesis. The chain is a check against
  *edits*, not against an adversary who owns the storage.

Both are answered the same way — by an anchor the attacker cannot reach. See
`acp.audit.checkpoint`: the head is committed to the repository, the same shape
ADR 0013 used for the schema baseline, and a verifier holding that anchor detects
both truncation and rewrite. **A chain plus an external anchor is tamper-evident;
a chain alone is tamper-evident to anybody who already knows where it should
end.** Saying so is the point of writing it down.

**Sequence numbers are carried as well as hashes**, and not as a convenience.
They make a gap *legible*: a verifier that stops at a broken link can say "entry
41,208" rather than "somewhere". They are also inside the hash, so they cannot be
renumbered to hide a removal.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from acp.audit.record import AUDIT_VERSION, AuditRecord, canonical

GENESIS: Final = "0" * 64
"""The `prev` of the first entry.

A fixed, obviously-not-a-hash value rather than an empty string or `None`, so
that "this is the start of the chain" is a claim the format states rather than
one a reader infers from an absence. A verifier can then check the first entry
as strictly as every other one.
"""

SEQ_START: Final = 1
"""Entries are numbered from one, not zero. The first question asked of a chain
is how many entries it has, and `seq` of the last entry answering that directly
is worth more than the symmetry."""


def link(*, prev: str, seq: int, payload: Mapping[str, Any]) -> str:
    """The hash binding this record to the one before it.

    Over `[AUDIT_VERSION, prev, seq, canonical(payload)]` — a JSON array rather
    than concatenated strings, because concatenation is how two different tuples
    hash to one digest. ``"a" + "bc"`` and ``"ab" + "c"`` are the same bytes; a
    length-delimited encoding of the parts is not, and the ambiguity is exactly
    the kind an attacker looks for.

    The version is *inside* the hash so a chain written under one rule cannot be
    verified under another and silently pass.
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
    """The record as a plain mapping, already redacted.

    A mapping rather than an `AuditRecord`, because an entry read back from disk
    may have been written by a *newer* version of this code carrying fields this
    one does not know about. Parsing it into today's dataclass would discard
    them — and then verify a hash computed over the fields that were discarded,
    reporting tampering on a file nobody touched. **A verifier must hash what is
    there, not what it understands.**
    """

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "prev": self.prev, "hash": self.hash, "record": dict(self.record)}

    @property
    def valid(self) -> bool:
        """Whether this entry's own hash matches its contents and position."""
        return self.hash == link(prev=self.prev, seq=self.seq, payload=self.record)


def next_entry(*, head: str, seq: int, payload: Mapping[str, Any]) -> Entry:
    """The entry that follows ``head``."""
    return Entry(seq=seq, prev=head, hash=link(prev=head, seq=seq, payload=payload), record=payload)


class Chain:
    """The head of a chain being appended to, in this process.

    Deliberately tiny and deliberately not the thing that writes: it holds a
    position and produces entries, and `acp.audit.sink` decides where they go and
    what happens when that fails. Keeping them apart is what makes the whole
    chaining rule testable without a filesystem, and what lets a Postgres-backed
    sink arrive later as a class rather than a redesign.
    """

    def __init__(self, head: str = GENESIS, seq: int = SEQ_START - 1) -> None:
        self._head = head
        self._seq = seq

    @property
    def head(self) -> str:
        return self._head

    @property
    def length(self) -> int:
        return self._seq

    def append(self, record: AuditRecord | Mapping[str, Any]) -> Entry:
        """Extend the chain by one, advancing the head."""
        payload = record.as_dict() if isinstance(record, AuditRecord) else dict(record)
        entry = next_entry(head=self._head, seq=self._seq + 1, payload=payload)
        self._head = entry.hash
        self._seq = entry.seq
        return entry


# ---------------------------------------------------------------------------
# Verification (task 57's engine — the CLI is a thin wrapper over this)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Break:
    """Where a chain stops being one, and in what way.

    The sequence number matters more than the message. An auditor told "the chain
    is broken" has to read the whole file; one told "entry 41,208's `prev` does
    not match entry 41,207" has a line number and a time window.
    """

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

    anchor_hash: str | None = None
    """The hash of the entry at the sequence number an anchor names, if one was
    asked for.

    Captured during the walk rather than by keeping every hash, so verifying a
    chain costs O(1) memory however long it is. A verifier that had to hold the
    whole chain to check one anchor would be a verifier nobody runs on the file
    that matters most.
    """
    """Lines that were not JSON, or were JSON of the wrong shape.

    Counted rather than raised, and **counted as a failure** — unlike the
    decision-log reader (ADR 0045), which skips a bad line and carries on because
    a simulator that dies on line 40,000 has answered no question at all. The
    opposite call here, for the opposite reason: a line this cannot read is a
    line whose contribution to the chain it cannot check, and reporting "verified"
    over a file with a hole in it is precisely the lie the chain exists to make
    impossible.
    """

    @property
    def intact(self) -> bool:
        return not self.breaks and not self.unreadable

    def describe(self) -> str:
        if self.intact:
            return f"{self.entries} entries, chain intact, head {self.head[:16]}…"
        lines = [f"{self.entries} entries read, {len(self.breaks)} break(s)"]
        if self.unreadable:
            lines.append(f"{self.unreadable} unreadable line(s)")
        lines.extend(f"  {b.describe()}" for b in self.breaks)
        return "\n".join(lines)


def _entry_from(payload: object) -> Entry | None:
    """An entry, or ``None`` if this object is not one.

    Every field is checked for the type it must have. A `seq` that arrived as a
    string is not a sequence number this can reason about, and coercing it would
    let a hand-edited file walk straight past the check.
    """
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
    return Entry(seq=seq, prev=prev, hash=digest, record=record)


def verify(
    lines: Iterable[str], *, expected_head: str = GENESIS, anchor_seq: int | None = None
) -> Verification:
    """Walk a chain and report every way it is not one.

    Takes lines rather than a path so the caller decides where the chain comes
    from — a file, a pipe, a test's list of strings, an object store — and so a
    chain larger than memory streams rather than loads.

    **Every break is reported, not just the first.** A verifier that stops at the
    first one turns an investigation into a series of round trips, and the shape
    of the damage is itself evidence: one broken link is an edit, a break at
    every entry after some point is a rewrite that started there.
    """
    import json  # noqa: PLC0415 — local, so this module's import graph stays hash-only

    breaks: list[Break] = []
    unreadable = 0
    head = expected_head
    seq = SEQ_START - 1
    count = 0
    anchor_hash: str | None = None

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

        if anchor_seq is not None and entry.seq == anchor_seq:
            anchor_hash = entry.hash

        # The walk continues from what the file *claims*, not from what it
        # should have been. Re-deriving the head would make one edit cascade
        # into a break on every subsequent line, burying the location of the
        # actual change under thousands of consequences of it.
        head = entry.hash
        seq = entry.seq

    return Verification(
        entries=count,
        head=head,
        breaks=tuple(breaks),
        unreadable=unreadable,
        anchor_hash=anchor_hash,
    )
