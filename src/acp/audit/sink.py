"""Where entries go, and what happens when they cannot go there.

Task 56. `acp.audit.chain` computes links; this decides where they land. Kept
apart on purpose: the chaining rule is then testable without a filesystem, and a
Postgres- or object-store-backed sink arrives later as a class rather than a
redesign.

**Three things this module gets to be opinionated about.**

**1. A restart continues the chain; it does not start a second one.** On open,
the head and sequence are recovered from the last entry already in the file. A
sink that began at `GENESIS` every time the process restarted would write a file
containing several valid chains end to end, and a verifier walking it would
report a break at every restart — which trains everybody to ignore breaks, which
is the only outcome worse than not having a verifier.

**2. A tail this cannot read stops the process.** A half-written final line —
the ordinary result of a crash mid-write — leaves a file whose tail is not an
entry. Two options: truncate it and carry on, or refuse to start. Truncating an
audit log to make it parse is the single thing this module must never do, and it
would be *automatic evidence destruction* in the exact circumstances where
somebody later asks what happened. So it refuses, loudly, naming the line — and
an operator makes a deliberate, recorded decision about a file they can still see.

**3. `fsync` on every entry.** Expensive, and correct. A record buffered in the
kernel when the machine loses power is a record that describes a call which
really happened, and it is precisely the crash-adjacent window an investigation
cares about. The cost is real and is stated rather than hidden: this bounds
write throughput to the disk's sync rate, and Phase 8 measures it. `fsync=False`
exists for tests and for a deployment that has consciously traded the guarantee.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Protocol

from acp.audit.chain import GENESIS, SEQ_START, Chain, Entry
from acp.audit.record import AuditRecord
from acp.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class AuditSink(Protocol):
    """The three operations an audit writer needs.

    Deliberately not a general file interface, and deliberately with no `read`.
    Verification is a separate program walking the artifact from the outside
    (task 57); giving the writing path a way to read its own chain back would
    invite a "repair" function, and a log that can repair itself is a log that
    can be repaired by whoever broke it.
    """

    def append(self, record: AuditRecord) -> Entry:
        """Chain this record and durably record it. Raises if it cannot."""

    @property
    def head(self) -> str:
        """The hash of the most recent entry."""

    @property
    def length(self) -> int:
        """How many entries this sink has written or recovered."""

    def close(self) -> None:
        """Release whatever this sink holds open.

        Part of the protocol rather than an implementation detail of the file
        sink, because *every* sink owns something — a handle, a connection, a
        batch not yet flushed. Leaving it off meant `gateway_from_settings`
        closed the secret store, the exchanger and the key cache and silently
        leaked the one resource whose whole purpose is durability.
        """


class MemoryAuditSink:
    """A chain in a list, for tests and for `--dry-run`.

    Real chaining, no filesystem — so every property about linking, ordering and
    verification is exercised by the fast suite rather than only by whatever
    happens to touch a temporary directory.
    """

    def __init__(self) -> None:
        self._chain = Chain()
        self.entries: list[Entry] = []

    def append(self, record: AuditRecord) -> Entry:
        entry = self._chain.append(record)
        self.entries.append(entry)
        return entry

    @property
    def head(self) -> str:
        return self._chain.head

    @property
    def length(self) -> int:
        return self._chain.length

    def close(self) -> None:
        """Nothing to release. Present because the protocol requires it, and a
        test double that cannot be closed like the real thing is one that hides
        the bug where somebody forgets to."""

    def lines(self) -> list[str]:
        """The entries as they would have been written, for `verify`."""
        return [json.dumps(entry.as_dict(), separators=(",", ":")) for entry in self.entries]


def recover(path: Path) -> tuple[str, int]:
    """The head and sequence to continue from, or the reason this cannot start.

    Streams the file rather than seeking to the end. That is O(n) at startup and
    it is the right trade: a tail-seek has to guess where the last line begins,
    and a careless one resumes from a *corrupted* tail — which writes a valid
    chain on top of a broken one and hides exactly what the format exists to
    show. The startup cost is paid once per process; the wrong answer is paid
    once, forever, by whoever is investigating.

    Raises `ConfigurationError` when the last line is not an entry. See the
    module docstring: refusing beats truncating.
    """
    if not path.exists():
        return GENESIS, SEQ_START - 1

    head, seq, number, last_line = GENESIS, SEQ_START - 1, 0, 0
    with path.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                msg = (
                    f"{path} line {number} is not JSON, so the audit chain cannot be "
                    f"continued without either ignoring it or truncating the file. "
                    f"Both destroy evidence, so this gateway refuses to start. "
                    f"Inspect the file, archive it, and move it aside deliberately. "
                    f"({exc.msg})"
                )
                raise ConfigurationError(msg) from exc
            if not isinstance(parsed, dict) or not isinstance(parsed.get("hash"), str):
                msg = (
                    f"{path} line {number} is JSON but not an audit entry. The chain "
                    f"cannot be continued from it; inspect and archive the file rather "
                    f"than letting this gateway write past it."
                )
                raise ConfigurationError(msg)
            head, last_line = parsed["hash"], number
            recorded = parsed.get("seq")
            seq = recorded if isinstance(recorded, int) and not isinstance(recorded, bool) else seq

    if last_line:
        logger.info(
            "audit.resumed",
            extra={"path": str(path), "entries": seq, "head": head[:16]},
        )
    return head, seq


class FileAuditSink:
    """One JSON entry per line, appended, flushed and synced.

    JSON Lines rather than a database, for the reason ADR 0007 gives about
    structured logs: the artifact should be readable by `grep`, `jq`, a log
    shipper and a court, without this project's code being present. A format that
    needs its own reader is a format whose evidence expires when the reader stops
    building.

    The handle is held open for the process's lifetime. Reopening per write would
    be slower *and* weaker: it opens a window in which the path can be swapped
    between entries, and an audit sink following a rename to somewhere else is
    the whole attack.
    """

    def __init__(self, path: Path, *, fsync: bool = True) -> None:
        head, seq = recover(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Line buffered, so a crash loses at most the entry being written rather
        # than everything since the last block filled.
        self._handle = path.open("a", encoding="utf-8", buffering=1)
        self._path = path
        self._chain = Chain(head=head, seq=seq)
        self._fsync = fsync

    def append(self, record: AuditRecord) -> Entry:
        """Chain and write, or raise.

        The entry is chained *before* it is written and the head advances only
        after the write succeeds — so a failed write leaves the chain where it
        was rather than skipping a sequence number that nothing will ever fill.
        A gap is indistinguishable from a deletion to anybody reading later.
        """
        entry = self._chain.append(record)
        try:
            self._handle.write(json.dumps(entry.as_dict(), separators=(",", ":")) + "\n")
            self._handle.flush()
            if self._fsync:
                os.fsync(self._handle.fileno())
        except OSError:
            # Rewind, so the next attempt reuses this sequence number. The caller
            # decides whether an unwritable record stops the call (it does, by
            # default) — see `acp.audit.writer`.
            self._chain = Chain(head=entry.prev, seq=entry.seq - 1)
            raise
        return entry

    @property
    def head(self) -> str:
        return self._chain.head

    @property
    def length(self) -> int:
        return self._chain.length

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        self._handle.close()
