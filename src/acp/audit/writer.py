"""`AuditLog`: the request path's audit seam, and the one place fail-closed is decided.

A dedicated sink rather than a `logging.Handler`, because the operational log is filtered,
rotated and swallows its own errors, while an unrecordable call must not happen. Redaction
(`acp.observability.log.redact`) runs before chaining so the hash covers the bytes on disk.
`arecord` runs blocking writes on a worker thread, serialised one at a time, so `fsync` does
not stall the event loop while the caller still waits for durability (ADR 0053).
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Callable, Mapping
from typing import Any

from anyio import CapacityLimiter, to_thread

from acp.audit.chain import Entry
from acp.audit.record import AuditRecord, Category, Outcome, recordable_tool
from acp.audit.sink import AuditSink
from acp.exceptions import AuditUnavailableError
from acp.observability import metrics
from acp.observability.log import redact

logger = logging.getLogger(__name__)

PUBLISH_FAILURE_EVENT = "audit.publish_failed"
"""Logged at WARNING when a watcher raises; the entry is already durable."""

FAILURE_EVENT = "audit.write_failed"
"""Logged to the operational log at ERROR when the chain cannot be written."""


class AuditLog:
    """Records auditable facts and, when `required`, refuses the call if it cannot.

    The clock is injectable for tests.
    """

    def __init__(
        self,
        sink: AuditSink,
        *,
        required: bool = True,
        clock: Callable[[], float] = time.time,
        published: Callable[[Entry], None] | None = None,
    ) -> None:
        self._sink = sink
        self._required = required
        self._clock = clock
        self._limiter: CapacityLimiter | None = None
        self._published = published
        """Called with each entry after it is durable (the console's feed); see `_publish`."""

    @property
    def head(self) -> str:
        return self._sink.head

    @property
    def length(self) -> int:
        return self._sink.length

    @property
    def required(self) -> bool:
        return self._required

    def close(self) -> None:
        """Release the sink; called by `gateway_from_settings` at shutdown."""
        self._sink.close()

    def _serialiser(self) -> CapacityLimiter:
        """A `CapacityLimiter(1)` serialising threaded writes, created lazily (needs a loop)."""
        if self._limiter is None:
            self._limiter = CapacityLimiter(1)
        return self._limiter

    async def arecord(
        self,
        category: Category,
        event: str,
        *,
        subject: str | None = None,
        actor: str | None = None,
        tenant: str | None = None,
        tool: str | None = None,
        upstream: str | None = None,
        rule: str | None = None,
        outcome: Outcome | None = None,
        reason: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> Entry | None:
        """Async `record` used by the request path; same semantics and exceptions.

        Runs on a worker thread only when the sink blocks; the caller still waits for
        durability. The signature is repeated so typos are type errors.
        """
        call = functools.partial(
            self.record,
            category,
            event,
            subject=subject,
            actor=actor,
            tenant=tenant,
            tool=tool,
            upstream=upstream,
            rule=rule,
            outcome=outcome,
            reason=reason,
            detail=detail,
        )
        if not self._sink.blocking:
            # The thread hop costs more than a page-cache write (ADR 0053).
            entry = call()
        else:
            entry = await to_thread.run_sync(call, limiter=self._serialiser())
        self._publish(entry)
        return entry

    def _publish(self, entry: Entry | None) -> None:
        """Hand a durable entry to the watcher; skipped for ``None`` (failed, not required).

        Runs on the event loop, not inside `record`, because the console hub's `asyncio.Event`
        is not thread safe; and only after the write, so the console never runs ahead of the
        chain (ADR 0056).
        """
        if entry is None or self._published is None:
            return
        try:
            self._published(entry)
        except Exception:
            # A watcher must never fail a request; the entry is already durable.
            logger.warning(PUBLISH_FAILURE_EVENT, exc_info=True)

    def record(
        self,
        category: Category,
        event: str,
        *,
        subject: str | None = None,
        actor: str | None = None,
        tenant: str | None = None,
        tool: str | None = None,
        upstream: str | None = None,
        rule: str | None = None,
        outcome: Outcome | None = None,
        reason: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> Entry | None:
        """Chain and store one fact.

        Returns:
            The entry, or ``None`` if the write failed and audit is not required.

        Raises:
            AuditUnavailableError: The write failed and audit is required.
        """
        record = AuditRecord(
            category=category,
            event=event,
            at=self._clock(),
            subject=subject,
            actor=actor,
            tenant=tenant,
            tool=recordable_tool(tool),
            upstream=upstream,
            rule=rule,
            outcome=outcome,
            reason=reason,
            # Redact before hashing so the hash covers the bytes on disk.
            detail=_clean(detail),
        )

        try:
            entry = self._sink.append(record)
        except OSError as exc:
            metrics.record_audit_write(outcome="failed")
            logger.error(  # noqa: TRY400 — fields matter, not a traceback
                FAILURE_EVENT,
                extra={
                    "error": str(exc),
                    "audit_event": event,
                    "required": self._required,
                    "consequence": (
                        "the call was refused because it could not be recorded"
                        if self._required
                        else "the call proceeded and there is no record of it"
                    ),
                },
            )
            if self._required:
                raise AuditUnavailableError("this call could not be completed") from exc
            return None
        metrics.record_audit_write(outcome="written")
        return entry


def _clean(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    """Redact a detail mapping, returning ``{}`` for anything that is not one."""
    if not detail:
        return {}
    cleaned = redact(dict(detail))
    return cleaned if isinstance(cleaned, dict) else {}
