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

import fcntl
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

    @property
    def blocking(self) -> bool:
        """Whether `append` waits on hardware.

        Task 61 moved the audit write to a worker thread so an `fsync` could
        not park the event loop. Task 61's own measurement then showed the
        thread hop is a **fixed cost** — two context switches and a limiter
        acquisition — that is worth paying only when the write actually waits:
        with `fsync` off, offloading cost 29% of throughput for nothing.

        So the sink declares it, because the sink is the only thing that knows.
        The rule is not "is this write slow" (unknowable) but the sharper
        physical one: **does it wait on hardware?** `fsync` does. A `write()`
        into a line-buffered file copies into the kernel's page cache and
        returns, which is not something to leave the event loop for.
        """
        ...

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

    blocking = False
    """Nothing to wait for: a list append. Offloading it would be pure cost."""

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
        # **Unbuffered, and that is a correctness requirement rather than a
        # tuning choice.**
        #
        # `append` rewinds the chain when a write fails, so the sequence number
        # is reused rather than skipped — a gap is indistinguishable from a
        # deletion to anybody reading later. That reasoning is right and a
        # buffered writer silently defeats it: CPython keeps the bytes it could
        # not flush, so the *next* successful flush emits the failed line first
        # and then the retried one. Two entries with the same `seq`, a `prev`
        # that matches neither, and `acp audit verify` reporting tampering on a
        # file nobody touched. One transient ENOSPC is enough.
        #
        # Raw binary has no such buffer: a write reaches the descriptor or it
        # does not, and `append` can tell which by counting bytes.
        self._handle = path.open("ab", buffering=0)
        self._torn = False
        self._path = path
        # Taken **after** the handle is open and **before** the chain head is
        # trusted, so no second writer can be recovering the same tail
        # concurrently. See `_take_exclusive_lock`.
        self._take_exclusive_lock()
        self._chain = Chain(head=head, seq=seq)
        self._fsync = fsync

    def _take_exclusive_lock(self) -> None:
        """One writer per chain file, enforced rather than documented (ADR 0063).

        ADR 0050 says "one process, one file" and nothing made it true. Two
        processes opening the same path each recovered the same head and then
        interleaved entries from that head — every entry after the first
        collision carries a `prev` that does not match the line above it, so the
        chain is corrupt from that moment, `acp audit verify` reports tampering,
        and **nothing failed at write time**. A hash chain whose integrity claim
        can be broken by starting the service twice is a claim about a
        deployment convention, not about the file.

        `flock` is advisory, per open file description, and released
        automatically when the process dies — which is the behaviour wanted for
        a crash: the next start takes the lock rather than finding a stale one
        nobody can clear. It does not span NFS reliably, and that limit is in
        the threat model rather than defended against here.
        """
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._handle.close()
            msg = (
                f"another process is already writing the audit chain at "
                f"{str(self._path)!r}. Two writers interleave entries from one "
                f"recovered head, which corrupts the chain silently — every "
                f"entry after the collision has a `prev` that does not match the "
                f"line above it, and nothing fails until `acp audit verify` "
                f"reports tampering on a file nobody touched."
            )
            raise ConfigurationError(msg) from exc

    @property
    def blocking(self) -> bool:
        """True exactly when this sink calls `fsync`.

        Without it the write is `write()` plus `flush()` into the page cache —
        microseconds, and not worth a thread. With it the call waits for the
        disk, and every other request in the process waits with it unless the
        writer moves off the loop.
        """
        return self._fsync

    def append(self, record: AuditRecord) -> Entry:
        """Chain and write, or raise.

        The entry is chained *before* it is written and the head advances only
        after the write succeeds — so a failed write leaves the chain where it
        was rather than skipping a sequence number that nothing will ever fill.
        A gap is indistinguishable from a deletion to anybody reading later.
        """
        if self._torn:
            # A previous append left a partial line on disk. Appending after it
            # would write a valid entry behind a torn one and bury the damage in
            # the middle of a file that still looks mostly fine.
            msg = (
                f"audit chain {str(self._path)!r} has a partially written entry and "
                f"this process will not write past it. The file needs a human: the "
                f"tail is not a record, and every entry after it would be chained "
                f"onto something that is not there."
            )
            raise OSError(msg)

        entry = self._chain.append(record)
        line = (json.dumps(entry.as_dict(), separators=(",", ":")) + "\n").encode("utf-8")
        # The file's own length, not a counter. A raw write can raise *after*
        # putting bytes on the descriptor, and then its return value never
        # arrives — so counting what `write` reports would miss exactly the case
        # this needs to catch. In append mode every write lands at the end, so
        # the size before and after is the honest measure of what reached disk.
        before = os.fstat(self._handle.fileno()).st_size
        written = 0
        try:
            while written < len(line):
                # A raw write may be short. Unhandled, that silently truncates an
                # entry and the truncation is the last thing in the file, which is
                # exactly where nobody looks.
                sent = self._handle.write(line[written:])
                if not sent:
                    msg = f"audit chain {str(self._path)!r}: the descriptor accepted no bytes"
                    raise OSError(msg)
                written += sent
            if self._fsync:
                os.fsync(self._handle.fileno())
        except OSError:
            landed = os.fstat(self._handle.fileno()).st_size - before
            if landed:
                # Bytes reached the file. Rewinding now would reuse the sequence
                # number and write a second copy *after* the torn one, so the
                # chain would carry the damage rather than stop at it.
                self._torn = True
                raise
            # Nothing was written, so the entry does not exist and the sequence
            # number is free again. The caller decides whether an unwritable
            # record stops the call (it does, by default) — see `acp.audit.writer`.
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
        # Closing the descriptor releases the lock; doing it explicitly first
        # keeps the two facts in one place for anybody reading this.
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ValueError):  # pragma: no cover — already closed
            pass
        # No flush: the handle is unbuffered, so there is nothing held back —
        # which is the property this sink depends on. See `__init__`.
        self._handle.close()
