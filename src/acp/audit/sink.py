"""Audit sinks: where chained entries are stored.

On open, the file sink resumes the chain from its last entry. An unreadable tail (e.g. a
crash mid-write) stops startup rather than being truncated, since truncation destroys
evidence. Each entry is `fsync`ed by default, bounding throughput to the disk's sync rate
(measured in ``perf/``); `fsync=False` trades that durability away (ADR 0053).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import IO, Protocol

import fcntl  # POSIX only, like the deployment target (a Linux container)

from acp.audit.chain import GENESIS, SEQ_START, Chain, Entry
from acp.audit.record import AuditRecord
from acp.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class AuditSerialisationError(OSError):
    """A record that is not strict JSON, raised before the chain advances.

    An `OSError` so the writer treats it like a failed disk write.
    """


class AuditSink(Protocol):
    """What an audit writer needs; no `read`, since verification runs separately from outside."""

    @property
    def blocking(self) -> bool:
        """Whether `append` waits on hardware (e.g. `fsync`), so the writer offloads it to a thread.

        The thread hop has a fixed cost, so non-blocking sinks run inline (ADR 0053).
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
        """Release whatever this sink holds open."""


class MemoryAuditSink:
    """A real chain held in a list, for tests and `--dry-run`."""

    def __init__(self) -> None:
        self._chain = Chain()
        self.entries: list[Entry] = []

    blocking = False
    """A list append never waits on hardware."""

    def append(self, record: AuditRecord) -> Entry:
        try:
            entry = self._chain.append(record)
        except (TypeError, ValueError) as exc:
            # Same refusal as the file sink.
            raise AuditSerialisationError(f"audit record is not JSON-encodable: {exc}") from exc
        self.entries.append(entry)
        return entry

    @property
    def head(self) -> str:
        return self._chain.head

    @property
    def length(self) -> int:
        return self._chain.length

    def close(self) -> None:
        """Nothing to release; required by the protocol."""

    def lines(self) -> list[str]:
        """The entries as they would have been written, for `verify`."""
        return [json.dumps(entry.as_dict(), separators=(",", ":")) for entry in self.entries]


def recover(path: Path) -> tuple[str, int]:
    """The head and sequence to continue from, found by streaming the whole file (O(n)).

    Raises:
        ConfigurationError: A line is not an audit entry; refusing beats truncating.
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
    """JSON Lines chain file, appended, flushed and synced; readable with plain tools (ADR 0007).

    The handle stays open for the process lifetime, so the path cannot be swapped between
    writes. One writer only (ADR 0070): a thread lock serialises `append`, and an exclusive
    `flock` makes a second process on the same path refuse to start.
    """

    def __init__(self, path: Path, *, fsync: bool = True) -> None:
        head, seq = recover(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Line buffered: a crash loses at most the entry being written.
        self._handle = path.open("a", encoding="utf-8", buffering=1)
        _claim(self._handle, path)
        self._path = path
        self._chain = Chain(head=head, seq=seq)
        self._fsync = fsync
        self._lock = threading.Lock()

    @property
    def blocking(self) -> bool:
        """True exactly when this sink calls `fsync`."""
        return self._fsync

    def append(self, record: AuditRecord) -> Entry:
        """Chain and write the record, or raise `OSError` leaving the head unchanged.

        Rewinding on failure avoids a sequence gap, which would look like a deletion.
        """
        # Unencodable values fail inside this try, before anything is written, so the head
        # never points at an entry that is not on disk.
        with self._lock:
            try:
                entry = self._chain.append(record)
                line = json.dumps(entry.as_dict(), separators=(",", ":"), allow_nan=False) + "\n"
            except (TypeError, ValueError) as exc:
                msg = f"audit record is not JSON-encodable: {exc}"
                raise AuditSerialisationError(msg) from exc
            try:
                self._handle.write(line)
                self._handle.flush()
                if self._fsync:
                    os.fsync(self._handle.fileno())
            except OSError:
                # Rewind so the next attempt reuses this seq; `acp.audit.writer` decides
                # whether the call is refused.
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
        # Also releases the advisory lock.
        self._handle.close()


def _claim(handle: IO[str], path: Path) -> None:
    """Take a non-blocking exclusive `flock`, or raise `ConfigurationError` naming the path.

    Advisory, so readers such as `acp audit verify` are unaffected.
    """
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        msg = (
            f"the audit chain at {path} is held by another process; two writers "
            f"would produce two chains in one file. Give each gateway its own path."
        )
        raise ConfigurationError(msg) from exc
