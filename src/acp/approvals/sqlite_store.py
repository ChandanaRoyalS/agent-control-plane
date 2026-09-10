"""Approvals that survive a restart.

The in-memory store is correct for one process and honest about being so, and
`ApprovalStore` was written as a protocol precisely so that the durable version
would be a class rather than a redesign (see `store.py`). This is that class.

**Why this one is worth having and the in-memory budgets are not.** ADR 0044
argues that in-memory rate limits are an *accuracy* cut: a restart gives
everybody a fresh allowance, which is unfair and briefly wrong and then correct
again. An approval is not like that. A gateway that answered `input_required`,
took a human's yes, and then restarted has lost a decision a person made — and
the caller is told no for a call that was approved. That is a correctness cut,
and it is the one ADR 0048's own "what this does not do" names first.

**Why SQLite.** The alternative shapes are a shared cache (Redis) or the primary
database somebody already runs (Postgres). Both are better for a replicated
deployment and both add a service to a system whose entire deployment story is
one container. SQLite is in the standard library, writes to a file next to the
audit chain, and turns "a restart loses every pending decision" into "a restart
loses nothing" — which is the whole of the correctness cut. It does *not* solve
the replicated case: two gateways with two files still cannot resolve each
other's tokens. That remains true, remains in the threat model, and is a
different sentence from the one this closes.

**Concurrency.** One connection, `check_same_thread=False`, and every mutation
inside `BEGIN IMMEDIATE` so that decide-and-consume cannot interleave with
another worker's read of the same row. WAL mode, because the reader (the
operator listing pending requests) must not block the writer (the request path
creating one).
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from acp.approvals.record import ApprovalRequest, State
from acp.approvals.store import DEFAULT_MAX_PENDING
from acp.exceptions import ConfigurationError

SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS approvals (
    token          TEXT PRIMARY KEY,
    fingerprint    TEXT NOT NULL,
    tenant         TEXT,
    subject        TEXT NOT NULL,
    tool           TEXT NOT NULL,
    rule           TEXT,
    created_at     REAL NOT NULL,
    expires_at     REAL NOT NULL,
    state          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    arguments_json TEXT,
    arguments_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS approvals_pending
    ON approvals (state, created_at);
CREATE INDEX IF NOT EXISTS approvals_tenant_pending
    ON approvals (tenant, state, created_at);
"""


class SqliteApprovalStore:
    """`ApprovalStore` over a file, with the same four operations.

    Nothing above this module knows where the record is, which was the point of
    the protocol.
    """

    def __init__(self, path: Path, *, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        self._path = path
        self._max_pending = max_pending
        self._lock = threading.Lock()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        except (OSError, sqlite3.Error) as exc:
            msg = f"cannot open the approval store at {str(path)!r}: {exc}"
            raise ConfigurationError(msg) from exc
        self._db.row_factory = sqlite3.Row
        # WAL so the operator's listing does not block the request path's
        # insert. FULL rather than NORMAL: an approval acknowledged to a person
        # and then lost to a power cut is the failure this class exists to
        # remove, and it is not worth trading for a write that is already off
        # the hot path.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Cursor]:
        """One mutation, serialised, atomic.

        `BEGIN IMMEDIATE` takes the write lock up front rather than on first
        write, which is what makes read-then-write inside this block safe
        against another worker doing the same thing — the shape that lets a
        token be decided twice or consumed twice.
        """
        with self._lock:
            cursor = self._db.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
            except BaseException:
                cursor.execute("ROLLBACK")
                raise
            cursor.execute("COMMIT")

    def create(self, request: ApprovalRequest) -> None:
        with self._write() as cursor:
            self._evict(cursor, request.tenant)
            cursor.execute(
                "INSERT OR REPLACE INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request.token,
                    request.fingerprint,
                    request.tenant,
                    request.subject,
                    request.tool,
                    request.rule,
                    request.created_at,
                    request.expires_at,
                    str(request.state),
                    request.reason,
                    request.arguments_json,
                    request.arguments_bytes,
                ),
            )

    def _evict(self, cursor: sqlite3.Cursor, tenant: str | None) -> None:
        """Make room, **within this tenant only**.

        The in-memory store evicted the globally-oldest pending request
        regardless of tenant or state, so 256 calls from any gated principal
        pushed every other tenant's pending approvals out — a cross-tenant
        denial of service costing one authenticated caller nothing (ADR 0063).

        Decided and consumed rows are swept first: they are history, not
        pressure, and evicting a *pending* request to make room while spent ones
        sit in the table costs somebody a re-ask for no reason.
        """
        cursor.execute(
            "DELETE FROM approvals WHERE state != ? AND expires_at < ?",
            (str(State.PENDING), _now(cursor)),
        )
        cursor.execute(
            "SELECT COUNT(*) AS held FROM approvals WHERE tenant IS ? AND state = ?",
            (tenant, str(State.PENDING)),
        )
        held = int(cursor.fetchone()["held"])
        surplus = held - self._max_pending + 1
        if surplus > 0:
            cursor.execute(
                "DELETE FROM approvals WHERE token IN ("
                "  SELECT token FROM approvals"
                "  WHERE tenant IS ? AND state = ?"
                "  ORDER BY created_at LIMIT ?"
                ")",
                (tenant, str(State.PENDING), surplus),
            )

    def get(self, token: str) -> ApprovalRequest | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM approvals WHERE token = ?", (token,)).fetchone()
        return _request(row) if row is not None else None

    def decide(self, token: str, *, approved: bool, reason: str = "") -> ApprovalRequest | None:
        with self._write() as cursor:
            row = cursor.execute("SELECT * FROM approvals WHERE token = ?", (token,)).fetchone()
            if row is None:
                return None
            held = _request(row)
            if held.state is not State.PENDING:
                # Already decided or already spent. Refusing to re-decide is
                # what makes `consume` meaningful.
                return held
            decided = held.decided(approved=approved, reason=reason)
            cursor.execute(
                "UPDATE approvals SET state = ?, reason = ? WHERE token = ? AND state = ?",
                (str(decided.state), decided.reason, token, str(State.PENDING)),
            )
            return decided

    def consume(self, token: str) -> None:
        with self._write() as cursor:
            cursor.execute(
                "UPDATE approvals SET state = ? WHERE token = ? AND state != ?",
                (str(State.CONSUMED), token, str(State.CONSUMED)),
            )

    def pending(self) -> tuple[ApprovalRequest, ...]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM approvals WHERE state = ? ORDER BY created_at",
                (str(State.PENDING),),
            ).fetchall()
        return tuple(_request(row) for row in rows)

    def __len__(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) AS n FROM approvals").fetchone()
        return int(row["n"])

    def close(self) -> None:
        with self._lock:
            self._db.close()


def _now(cursor: sqlite3.Cursor) -> float:
    """SQLite's clock, so the sweep does not depend on the caller having one."""
    return float(cursor.execute("SELECT unixepoch('subsec') AS now").fetchone()["now"])


def _request(row: sqlite3.Row) -> ApprovalRequest:
    return ApprovalRequest(
        token=row["token"],
        fingerprint=row["fingerprint"],
        tenant=row["tenant"],
        subject=row["subject"],
        tool=row["tool"],
        rule=row["rule"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        state=State(row["state"]),
        reason=row["reason"],
        arguments_json=row["arguments_json"],
        arguments_bytes=row["arguments_bytes"],
    )
