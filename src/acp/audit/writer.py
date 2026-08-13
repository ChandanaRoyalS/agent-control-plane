"""The seam the request path calls, and the one place fail-closed is decided.

Task 56. `chain` links, `sink` stores, and this is what the gateway actually
talks to — one method, one construction site for `AuditRecord`, one policy about
what happens when the write fails.

**Why this is not a logging handler.**

The tempting design is a `logging.Handler` that filters on the event names the
code already emits — `policy.denied`, `auth.exchanged` — and chains whatever
passes. One integration point, no call-site changes, and the event vocabulary
already exists. It is wrong for three reasons, and they are worth having
written down because the shortcut will look attractive again later:

1. **The operational log is level-filtered, sampled and rotated.** A chain over
   it breaks whenever somebody raises the log level, whenever logrotate runs,
   whenever a queue handler drops under pressure. Every one of those is a break
   that means nothing, and a verifier that cries wolf is a verifier nobody runs.
2. **`logging` swallows its own errors, by design.** A handler that cannot write
   calls `handleError` and the program carries on — which is correct for logs
   and fatal here, because the entire fail-closed guarantee is that an
   unrecordable call does not happen.
3. **It is interleaved with everybody else's lines.** httpx, uvicorn and the SDK
   log through the same root logger, so the artifact would be a chain threaded
   through somebody else's debug output.

**A compliance story that depends on your log level is not one.** So: a separate
sink, a separate file, a separate guarantee — and a record built here rather
than scraped from a `LogRecord`, so its schema is a thing this project decided
instead of a by-product of what somebody passed to `extra=`.

**The write happens on a thread, and the caller still waits for it (task 61).**
`record` is synchronous and does a synchronous `os.fsync`. Called directly from
an `async def` handler — as it was until task 61 — that syscall runs *on the
event loop*, so one request's durability stops every other request in the
process, including ones that write no audit record at all. Task 60 measured it:
`tools/list`, which never touches this module, was **12.6x slower at p95**.

`arecord` is the seam the request path uses now. It hands `record` to a worker
thread and awaits the result, so:

- the calling request still cannot proceed until its entry is durable — the
  fail-closed guarantee is untouched, which is the whole point of the exercise;
- the event loop is free while the disk works, so every *other* request keeps
  running;
- audit writes are serialised against each other by a `CapacityLimiter(1)`,
  because `Chain.append` mutates sequence state and two threads in it would
  interleave two entries onto one `prev` — corrupting the property the chain
  exists to provide, in exchange for throughput nobody asked for.

**And it only offloads when the sink says it blocks.** The hop is a fixed cost;
its benefit scales with how long the write waits. Measured: with `fsync` on,
offloading is worth 16% of throughput and cuts the p99 by 41%. With `fsync`
off, the same hop *costs* 29% — a page-cache write is not something to leave
the event loop for. `AuditSink.blocking` is the sink answering the only
question that matters here: does this wait on hardware?

`record` stays public and synchronous: the CLI, the tests and any future
non-async caller have no event loop to protect.

**Redaction runs before the entry is chained.** `acp.observability.log.redact`
is the same pass the operational log uses, so a field named `token` cannot be
written here either. Doing it in this order matters: the digest must cover
exactly the bytes that reach the file, or a verifier reading the file would
recompute a different hash and report tampering on a log nobody touched.
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Callable, Mapping
from typing import Any

from anyio import CapacityLimiter, to_thread

from acp.audit.chain import Entry
from acp.audit.record import AuditRecord, Category, Outcome
from acp.audit.sink import AuditSink
from acp.exceptions import AuditUnavailableError
from acp.observability import metrics
from acp.observability.log import redact

logger = logging.getLogger(__name__)

FAILURE_EVENT = "audit.write_failed"
"""Emitted to the *operational* log, at ERROR, when the chain cannot be written.

It has to go somewhere other than the audit log, because the audit log is the
thing that just failed. That sounds obvious and is exactly the kind of loop a
design like this falls into — the record of the record's failure needs a
different sink or it is not a record at all.
"""


class AuditLog:
    """Records auditable facts, and refuses the call when it cannot.

    Holds a clock so tests advance a number rather than sleeping, the same
    injection the rate limiter and the approval flow use.
    """

    def __init__(
        self,
        sink: AuditSink,
        *,
        required: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._sink = sink
        self._required = required
        self._clock = clock
        self._limiter: CapacityLimiter | None = None

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
        """Release the sink. Called by `gateway_from_settings` on the way out.

        The file sink deliberately holds its handle for the process's lifetime —
        reopening per write is slower *and* weaker, because it opens a window in
        which the path can be swapped between entries. The cost of that decision
        is that somebody has to close it, and "somebody" is the thing that owns
        the process's lifecycle, beside the store and the exchanger it already
        closes.
        """
        self._sink.close()

    def _serialiser(self) -> CapacityLimiter:
        """One writer at a time, created on first use.

        Lazy because an `AuditLog` is constructed in plenty of places that have
        no event loop — every unit test in this package, for one — and a
        primitive that needs one should not be built until somebody is actually
        going to await on it.

        A capacity limiter rather than a lock because it is the same object
        `to_thread.run_sync` already takes: one concept doing the serialising
        and the thread-slot accounting, rather than a lock guarding a pool that
        is separately bounded.
        """
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
        """`record`, on a worker thread, awaited. **The seam the request path uses.**

        Identical semantics to `record` — same record, same chain, same
        fail-closed refusal, same exception — differing only in where the
        blocking part runs. The caller is still suspended until the entry is
        durable, so a call this gateway cannot record still does not happen.

        What changes is everybody else: the event loop is free during the
        `fsync`, so requests that are not writing audit records stop paying for
        the ones that are.

        The signature is repeated rather than `**kwargs`-forwarded on purpose.
        This is the method the gateway actually calls, and a typo'd field name
        should be a type error here for exactly the reason `record` gives.
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
            # Nothing to wait for. The thread hop is two context switches and a
            # limiter acquisition, and task 61's own before/after measured that
            # paying it for a page-cache write costs 29% of throughput. The
            # sink is asked rather than guessed at — see `AuditSink.blocking`.
            return call()
        return await to_thread.run_sync(call, limiter=self._serialiser())

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
        """Chain and store one fact. Raises when it cannot and audit is required.

        Every field is named rather than taking a `**kwargs` bag, so a call site
        that invents a field is a type error rather than a column that appears in
        one per cent of rows. `detail` is the deliberate exception, and every key
        used in it is asserted in this module's tests.

        Returns the entry, or ``None`` when the write failed and this deployment
        has opted out of fail-closed. Callers ignore the return value; it exists
        for the tests that assert what was chained.
        """
        record = AuditRecord(
            category=category,
            event=event,
            at=self._clock(),
            subject=subject,
            actor=actor,
            tenant=tenant,
            tool=tool,
            upstream=upstream,
            rule=rule,
            outcome=outcome,
            reason=reason,
            # Redacted here, before the digest is taken, so the hash covers the
            # bytes that reach the file. See the module docstring.
            detail=_clean(detail),
        )

        try:
            entry = self._sink.append(record)
        except OSError as exc:
            metrics.record_audit_write(outcome="failed")
            logger.error(  # noqa: TRY400 — the message and fields are the point, not a traceback
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
    """Redact a detail mapping, and guarantee a mapping comes back.

    `redact` walks arbitrary structures and returns whatever shape it was given;
    this narrows the result for the type checker and, more usefully, means a
    caller passing something that is not a mapping gets an empty detail rather
    than a record whose shape differs from every other record.
    """
    if not detail:
        return {}
    cleaned = redact(dict(detail))
    return cleaned if isinstance(cleaned, dict) else {}
