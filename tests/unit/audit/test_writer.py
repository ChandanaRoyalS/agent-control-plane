"""Fail-closed, redaction order, and the record's shape.

Task 56. `AuditLog` is the seam the request path calls and the single place the
decision about an unwritable record is made.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

import anyio
import pytest

from acp.audit.chain import verify
from acp.audit.record import Category, Outcome
from acp.audit.sink import FileAuditSink, MemoryAuditSink
from acp.audit.writer import FAILURE_EVENT, AuditLog
from acp.exceptions import AuditUnavailableError


class BrokenSink:
    """A sink that cannot write, which is the only interesting failure here."""

    head = "0" * 64
    length = 0
    blocking = True
    """Declared blocking so the fail-closed tests exercise the *threaded* path:
    an exception has to cross the thread boundary to reach the caller, and that
    is the half of the guarantee task 61 could have broken."""

    def append(self, _record: Any) -> Any:
        raise OSError("no space left on device")

    def close(self) -> None:
        """Part of the protocol, so the double stays a double.

        `close` was added to `AuditSink` after a leaked handle, and mypy
        immediately reported this class as no longer satisfying it — which is
        the argument for putting `close` on the protocol rather than treating it
        as a detail of the file sink. A double that quietly diverges from the
        interface is one that stops testing the thing it stands for.
        """


def written(sink: MemoryAuditSink) -> list[dict[str, Any]]:
    return [json.loads(line)["record"] for line in sink.lines()]


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def test_an_unwritable_record_refuses_the_call() -> None:
    """**The guarantee.** An audit log that stops recording while the gateway
    keeps serving is worse than none, because the record then asserts by
    omission that nothing happened during the window somebody will ask about."""
    audit = AuditLog(BrokenSink(), required=True)

    with pytest.raises(AuditUnavailableError):
        audit.record(Category.AUTHORIZATION, "policy.decision", subject="alice")


def test_the_refusal_names_nothing_on_the_wire() -> None:
    """A caller told "the audit log is down" has learned which subsystem to
    attack in order to stop being recorded — a strictly more valuable thing to
    know than the fact they were refused."""
    audit = AuditLog(BrokenSink(), required=True)

    with pytest.raises(AuditUnavailableError) as caught:
        audit.record(Category.AUTHORIZATION, "policy.decision")

    assert "audit" not in str(caught.value).lower()
    assert "space" not in str(caught.value).lower()


def test_opting_out_lets_the_call_proceed(caplog: pytest.LogCaptureFixture) -> None:
    """`ACP_AUDIT_REQUIRED=false` is a real mode and a loud one."""
    audit = AuditLog(BrokenSink(), required=False)

    with caplog.at_level(logging.ERROR, logger="acp.audit.writer"):
        assert audit.record(Category.AUTHORIZATION, "policy.decision") is None

    [failure] = [r for r in caplog.records if r.message == FAILURE_EVENT]
    assert "no record of it" in getattr(failure, "consequence", "")


def test_the_failure_is_reported_somewhere_other_than_the_audit_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The record of the record's failure needs a different sink, or it is not a
    record at all. It goes to the operational log at ERROR, and to a metric."""
    audit = AuditLog(BrokenSink(), required=True)

    with (
        caplog.at_level(logging.ERROR, logger="acp.audit.writer"),
        pytest.raises(AuditUnavailableError),
    ):
        audit.record(Category.AUTHORIZATION, "policy.decision")

    assert [r for r in caplog.records if r.message == FAILURE_EVENT]


# ---------------------------------------------------------------------------
# Redaction, and its order
# ---------------------------------------------------------------------------


def test_a_credential_in_a_detail_is_redacted() -> None:
    sink = MemoryAuditSink()
    AuditLog(sink).record(
        Category.CREDENTIAL,
        "auth.exchanged",
        detail={"authorization": "Bearer super-secret", "audience": "acp-upstream-mock-a"},
    )

    [record] = written(sink)

    assert record["detail"]["authorization"] == "[redacted]"
    assert record["detail"]["audience"] == "acp-upstream-mock-a"


def test_redaction_happens_before_the_hash() -> None:
    """**The ordering that makes the file verifiable.**

    If the digest were taken over the unredacted record, a verifier reading the
    file would recompute a different hash and report tampering on a log nobody
    touched — the worst possible false positive from a tool whose only job is
    detecting real ones.
    """
    sink = MemoryAuditSink()
    AuditLog(sink).record(Category.CREDENTIAL, "auth.exchanged", detail={"token": "super-secret"})

    assert verify(sink.lines()).intact
    assert "super-secret" not in sink.lines()[0]


# ---------------------------------------------------------------------------
# The record's shape
# ---------------------------------------------------------------------------


def test_every_record_has_the_same_keys() -> None:
    """A record whose shape depends on the outcome is one no query can group by."""
    sink = MemoryAuditSink()
    audit = AuditLog(sink)
    audit.record(Category.AUTHORIZATION, "policy.decision", subject="alice")
    audit.record(
        Category.TOOL_CALL,
        "tool.called",
        subject="bob",
        tool="mock-a__search",
        outcome=Outcome.COMPLETED,
        detail={"anything": 1},
    )

    first, second = written(sink)

    assert first.keys() == second.keys()


def test_absent_fields_are_present_and_null() -> None:
    """Dropped and unknown are the same bytes to a verifier and different facts
    to an auditor."""
    sink = MemoryAuditSink()
    AuditLog(sink).record(Category.AUTHORIZATION, "policy.decision")

    [record] = written(sink)

    assert record["tenant"] is None
    assert "tenant" in record


def test_the_tenant_is_carried() -> None:
    """Present from the first version, so an archived chain never has to be
    migrated — rewriting one is exactly what the chain exists to detect."""
    sink = MemoryAuditSink()
    AuditLog(sink).record(Category.AUTHORIZATION, "policy.decision", tenant="acme")

    assert written(sink)[0]["tenant"] == "acme"


def test_the_clock_is_injected() -> None:
    """Tests advance a number rather than sleeping, the same injection the rate
    limiter and the approval flow use."""
    sink = MemoryAuditSink()
    AuditLog(sink, clock=lambda: 1786600000.0).record(Category.AUTHORIZATION, "policy.decision")

    assert written(sink)[0]["at"] == 1786600000.0


# ---------------------------------------------------------------------------
# `arecord` — the same guarantees, off the event loop (task 61, ADR 0053)
# ---------------------------------------------------------------------------


def test_arecord_chains_exactly_as_record_does() -> None:
    """Same record, same chain, same verifier. The only difference is where the
    blocking part runs, and a difference in *behaviour* would make the whole
    change a rewrite rather than a relocation."""
    sync_sink, async_sink = MemoryAuditSink(), MemoryAuditSink()
    fields: dict[str, Any] = {
        "subject": "alice",
        "actor": "agent-7",
        "tool": "mock-a__search",
        "outcome": Outcome.ALLOWED,
        "detail": {"argument_names": ["query"]},
    }

    AuditLog(sync_sink, clock=lambda: 1000.0).record(
        Category.AUTHORIZATION, "policy.decision", **fields
    )

    async def write() -> None:
        await AuditLog(async_sink, clock=lambda: 1000.0).arecord(
            Category.AUTHORIZATION, "policy.decision", **fields
        )

    anyio.run(write)
    assert async_sink.lines() == sync_sink.lines()


def test_arecord_still_refuses_when_it_cannot_write() -> None:
    """The guarantee the whole subsystem exists for. Moving the write to a
    thread must not turn a refusal into a shrug — the exception has to cross
    the thread boundary and reach the caller."""
    log = AuditLog(BrokenSink(), required=True)

    async def write() -> None:
        await log.arecord(Category.TOOL_CALL, "tool.called", subject="alice")

    with pytest.raises(AuditUnavailableError):
        anyio.run(write)


def test_arecord_honours_fail_open_when_configured() -> None:
    log = AuditLog(BrokenSink(), required=False)

    async def write() -> Any:
        return await log.arecord(Category.TOOL_CALL, "tool.called", subject="alice")

    assert anyio.run(write) is None


def test_concurrent_arecords_produce_one_intact_chain() -> None:
    """**The reason a limiter exists.**

    `Chain.append` mutates sequence state. Two threads inside it would read the
    same `prev`, write two entries claiming the same predecessor, and produce a
    file that fails verification — trading the property the chain exists to
    provide for throughput nobody asked for.

    Twenty concurrent writers, one intact chain, twenty entries.
    """
    sink = MemoryAuditSink()
    log = AuditLog(sink)

    async def write_many() -> None:
        async with anyio.create_task_group() as group:
            for index in range(20):
                group.start_soon(
                    lambda i=index: log.arecord(  # type: ignore[misc]
                        Category.TOOL_CALL, "tool.called", subject=f"user-{i}"
                    )
                )

    anyio.run(write_many)

    result = verify(iter(sink.lines()))
    assert result.entries == 20
    assert result.intact, result.describe()


def test_the_write_does_not_happen_on_the_calling_thread() -> None:
    """The point of the exercise, asserted directly.

    Task 60 measured the symptom — `tools/list`, which writes no audit record,
    was 12.6x slower at p95 because it was parked behind other requests'
    `fsync`. The cause was that the write ran on the event loop's thread. This
    asserts the cause is gone, rather than re-measuring the symptom.
    """
    seen: list[int] = []

    class ThreadNotingSink(MemoryAuditSink):
        blocking = True

        def append(self, record: Any) -> Any:
            seen.append(threading.get_ident())
            return super().append(record)

    log = AuditLog(ThreadNotingSink())

    async def write() -> int:
        await log.arecord(Category.TOOL_CALL, "tool.called", subject="alice")
        return threading.get_ident()

    caller = anyio.run(write)
    assert seen, "the sink was never called"
    assert seen[0] != caller, "the write ran on the caller's thread — the loop was blocked"


def test_the_event_loop_keeps_running_during_a_slow_write() -> None:
    """The property the fix buys, measured in the only way that discriminates.

    A sink that sleeps 200ms stands in for `fsync` on a busy disk, while a
    ticker advances every 5ms.

    **The obvious assertion — "20 ticks happened" — is worthless**, and this
    test asserted exactly that until a mutation proved it: with the write back
    on the event loop the ticks still all happen, merely afterwards. What
    distinguishes the two designs is *how many ticks have run at the moment the
    write completes*: all of them if the loop stayed free, none if it did not.
    """

    class SlowSink(MemoryAuditSink):
        blocking = True
        """A sink that sleeps *is* blocking, so this stays an honest stand-in
        for `fsync` rather than a double that gets the fast path by accident."""

        def append(self, record: Any) -> Any:
            time.sleep(0.2)
            return super().append(record)

    log = AuditLog(SlowSink())
    ticks = 0
    ticks_when_written = -1

    async def tick() -> None:
        nonlocal ticks
        for _ in range(20):
            await anyio.sleep(0.005)
            ticks += 1

    async def write() -> None:
        nonlocal ticks_when_written
        await log.arecord(Category.TOOL_CALL, "tool.called", subject="alice")
        ticks_when_written = ticks

    async def both() -> None:
        async with anyio.create_task_group() as group:
            group.start_soon(tick)
            group.start_soon(write)

    anyio.run(both)
    assert ticks == 20
    assert ticks_when_written == 20, (
        f"only {ticks_when_written} of 20 ticks had run when the write finished — "
        f"the event loop was parked for the duration of the write"
    )


def test_a_non_blocking_sink_is_not_offloaded() -> None:
    """The correction task 61's own measurement forced.

    Offloading is a fixed cost — two context switches and a limiter — that pays
    for itself only when the write waits on hardware. With `fsync` off it cost
    **29% of throughput** for nothing. So a sink that does not block is written
    inline, on the calling thread, and this asserts exactly that.
    """
    seen: list[int] = []

    class InlineSink(MemoryAuditSink):
        blocking = False

        def append(self, record: Any) -> Any:
            seen.append(threading.get_ident())
            return super().append(record)

    log = AuditLog(InlineSink())

    async def write() -> int:
        await log.arecord(Category.TOOL_CALL, "tool.called", subject="alice")
        return threading.get_ident()

    caller = anyio.run(write)
    assert seen == [caller], "a non-blocking write left the calling thread for no reason"


def test_the_file_sink_declares_blocking_exactly_when_it_syncs(tmp_path: Any) -> None:
    """The property is not a flag somebody sets; it is a fact about the write.

    `FileAuditSink.blocking` must track `fsync` itself, or the writer will make
    the wrong choice on a deployment that changed one and not the other.
    """
    syncing = FileAuditSink(tmp_path / "a.jsonl", fsync=True)
    buffered = FileAuditSink(tmp_path / "b.jsonl", fsync=False)
    try:
        assert syncing.blocking is True
        assert buffered.blocking is False
    finally:
        syncing.close()
        buffered.close()


def test_a_memory_sink_never_blocks() -> None:
    assert MemoryAuditSink().blocking is False
