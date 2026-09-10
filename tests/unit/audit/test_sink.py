"""Where entries land, and the two failures that must not be papered over.

Task 56. The chain's correctness is `test_chain.py`'s problem. This is about the
file: that a restart continues rather than starting a second chain, that a tail
this cannot read stops the process instead of being truncated away, and that a
write failure leaves no gap.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.audit.chain import GENESIS, verify
from acp.audit.record import AuditRecord, Category, Outcome
from acp.audit.sink import FileAuditSink, MemoryAuditSink, recover
from acp.exceptions import ConfigurationError


def record(index: int) -> AuditRecord:
    return AuditRecord(
        category=Category.TOOL_CALL,
        event="tool.called",
        at=1786600000.0 + index,
        subject="alice",
        tenant="acme",
        tool="mock-a__search",
        outcome=Outcome.COMPLETED,
    )


def sink_at(path: Path) -> FileAuditSink:
    """Never fsynced in tests. The guarantee is asserted by its absence being a
    deliberate argument in the sink's docstring, not by making the suite wait on
    a disk a thousand times."""
    return FileAuditSink(path, fsync=False)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def test_entries_are_one_json_object_per_line(tmp_path: Path) -> None:
    """JSON Lines so the artifact is readable by grep, jq, a log shipper and a
    court, without this project's code being present."""
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    for index in range(3):
        sink.append(record(index))
    sink.close()

    lines = path.read_text().splitlines()

    assert len(lines) == 3
    assert all(json.loads(line)["seq"] == number for number, line in enumerate(lines, start=1))


def test_what_is_written_verifies(tmp_path: Path) -> None:
    """The end-to-end property: a file this sink produced is a chain the
    verifier accepts. Asserted because the two are separate modules and the
    format is the only thing holding them together."""
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    for index in range(5):
        sink.append(record(index))
    sink.close()

    assert verify(path.read_text().splitlines()).intact


# ---------------------------------------------------------------------------
# Restarting
# ---------------------------------------------------------------------------


def test_a_restart_continues_the_chain(tmp_path: Path) -> None:
    """**The one that makes the verifier usable.**

    A sink that began at GENESIS on every start would write a file containing
    several valid chains end to end, and a verifier walking it would report a
    break at every restart — which trains everybody to ignore breaks, which is
    worse than having no verifier at all.
    """
    path = tmp_path / "audit.jsonl"
    first = sink_at(path)
    for index in range(3):
        first.append(record(index))
    head_before = first.head
    first.close()

    second = sink_at(path)
    assert second.head == head_before
    assert second.length == 3

    second.append(record(3))
    second.close()

    result = verify(path.read_text().splitlines())
    assert result.intact
    assert result.entries == 4


def test_an_absent_file_starts_at_genesis(tmp_path: Path) -> None:
    assert recover(tmp_path / "nothing.jsonl") == (GENESIS, 0)


def test_blank_lines_do_not_advance_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    sink.append(record(0))
    sink.close()
    path.write_text(path.read_text() + "\n\n")

    head, seq = recover(path)

    assert seq == 1
    assert head != GENESIS


# ---------------------------------------------------------------------------
# The tail this cannot read
# ---------------------------------------------------------------------------


def test_a_half_written_tail_refuses_to_start(tmp_path: Path) -> None:
    """**Refusing beats truncating, and it is not a close call.**

    A crash mid-write leaves a partial final line. Truncating it to make the file
    parse is automatic evidence destruction in exactly the circumstances where
    somebody later asks what happened — so the process stops, names the line, and
    a human decides about a file they can still see.
    """
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    sink.append(record(0))
    sink.close()
    with path.open("a") as handle:
        handle.write('{"seq": 2, "prev": "aaa", "ha')

    with pytest.raises(ConfigurationError, match="line 2"):
        sink_at(path)


def test_the_refusal_says_what_to_do(tmp_path: Path) -> None:
    """An operator hitting this at 3am needs the next action, not a stack trace.
    A message that only says "corrupt" invites exactly the `rm` this exists to
    prevent."""
    path = tmp_path / "audit.jsonl"
    path.write_text("not json at all\n")

    with pytest.raises(ConfigurationError) as caught:
        sink_at(path)

    assert "archive" in caught.value.message
    assert "refuses to start" in caught.value.message


def test_json_that_is_not_an_entry_also_refuses(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps({"level": "INFO", "event": "something else"}) + "\n")

    with pytest.raises(ConfigurationError, match="not an audit entry"):
        sink_at(path)


# ---------------------------------------------------------------------------
# Failing to write
# ---------------------------------------------------------------------------


def fail_once_after(sink: FileAuditSink, prefix_bytes: int) -> None:
    """Make the next write fail at the **raw descriptor**, after ``prefix_bytes``.

    The layer matters more than anything else in this helper, and getting it
    wrong is how the bug these tests exist for survived. A full disk fails when
    the kernel is asked to take bytes — under any buffer the sink happens to
    have. Patching the *top* of a buffered writer instead means the bytes never
    enter the buffer, so nothing is ever left there to replay, and a test
    written that way passes against the broken implementation and the fixed one
    alike.

    So this reaches through to whatever is actually talking to the descriptor:
    a `BufferedWriter`'s `raw` when there is one, and the handle itself when the
    sink is unbuffered. Both take bytes, so the test reads the same either way.
    """
    buffer = getattr(sink._handle, "buffer", None)  # noqa: SLF001
    raw = getattr(buffer, "raw", None) or sink._handle  # noqa: SLF001
    real = raw.write
    armed = {"yes": True}

    def flaky(data: bytes) -> int:
        if armed["yes"]:
            armed["yes"] = False
            if prefix_bytes:
                real(data[:prefix_bytes])
            raise OSError(28, "No space left on device")
        return int(real(data))

    raw.write = flaky  # type: ignore[method-assign]


def test_a_failed_write_leaves_no_gap(tmp_path: Path) -> None:
    """The sequence number is reused on the next attempt.

    A skipped number is indistinguishable from a deletion to anybody reading the
    chain later, so a write that fails must not consume one — otherwise a
    transient disk error is permanently recorded as evidence of tampering.
    """
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    sink.append(record(0))

    fail_once_after(sink, prefix_bytes=0)
    with pytest.raises(OSError, match="No space"):
        sink.append(record(1))

    entry = sink.append(record(1))
    sink.close()

    assert entry.seq == 2
    assert verify(path.read_text().splitlines()).intact


def test_a_failed_write_does_not_replay_itself_on_the_next_flush(tmp_path: Path) -> None:
    """**The bug this test's neighbour was written to catch and could not.**

    `append` rewinds the chain so the sequence number is reused, which is right.
    A *buffered* writer silently defeats it: CPython keeps the bytes it could
    not flush, so the next successful flush emits the failed line first and then
    the retried one — two entries with the same `seq`, a `prev` matching
    neither, and `acp audit verify` reporting tampering on a file nobody
    touched. One transient ENOSPC was enough.

    The original test passed against that bug because it swapped the handle for
    a double with no buffer, so the property in its name was never exercised.
    This one fails the real thing on a real descriptor.
    """
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    sink.append(record(0))

    fail_once_after(sink, prefix_bytes=0)
    with pytest.raises(OSError):
        sink.append(record(1))

    sink.append(record(1))
    sink.append(record(2))
    sink.close()

    lines = [line for line in path.read_text().splitlines() if line.strip()]
    seqs = [json.loads(line)["seq"] for line in lines]

    assert seqs == [1, 2, 3], f"the failed entry was replayed: {seqs}"
    assert len(seqs) == len(set(seqs))
    assert verify(lines).intact


def test_a_torn_write_stops_the_sink_rather_than_being_buried(tmp_path: Path) -> None:
    """A write that puts *some* bytes down and then fails cannot be rewound.

    Reusing the sequence number would append a valid entry behind a truncated
    one, so the chain would carry the damage into the middle of a file that
    still looks mostly fine. Refusing means the tail is the last thing in the
    file, which is where somebody will actually find it.
    """
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    sink.append(record(0))

    fail_once_after(sink, prefix_bytes=20)
    with pytest.raises(OSError, match="No space"):
        sink.append(record(1))

    with pytest.raises(OSError, match="partially written"):
        sink.append(record(2))

    # Closed explicitly: `filterwarnings = ["error"]` turns a leaked handle into
    # a ResourceWarning that surfaces inside whichever *later* test happens to
    # trigger the collection, which is a debugging afternoon nobody needs.
    sink.close()


# ---------------------------------------------------------------------------
# The in-memory sink
# ---------------------------------------------------------------------------


def test_the_memory_sink_chains_for_real() -> None:
    """It is a test double for the *filesystem*, not for the chaining — so every
    property about linking is exercised by the fast suite rather than only by
    whatever happens to touch a temporary directory."""
    sink = MemoryAuditSink()
    for index in range(4):
        sink.append(record(index))

    assert verify(sink.lines()).intact
    assert sink.length == 4


def test_a_second_writer_on_one_chain_file_is_refused(tmp_path: Path) -> None:
    """**ADR 0050 said "one process, one file" and nothing made it true.**

    Two processes opening the same path each recover the same head and then
    interleave entries from it. Every entry after the first collision carries a
    `prev` that does not match the line above it, so the chain is corrupt from
    that moment, `acp audit verify` reports tampering, and *nothing fails at
    write time*. A hash chain whose integrity claim can be broken by starting
    the service twice is a claim about a deployment convention, not about the
    file.
    """
    path = tmp_path / "audit.jsonl"
    first = FileAuditSink(path)

    with pytest.raises(ConfigurationError, match="already writing"):
        FileAuditSink(path)

    first.close()


def test_the_lock_is_released_when_the_sink_is_closed(tmp_path: Path) -> None:
    """Otherwise a restart in the same process — a test, a reload — would find
    a lock nobody can clear."""
    path = tmp_path / "audit.jsonl"
    FileAuditSink(path).close()

    reopened = FileAuditSink(path)
    reopened.close()


def test_a_second_writer_never_gets_far_enough_to_corrupt_the_chain(tmp_path: Path) -> None:
    """The property the refusal protects, asserted on the file rather than on
    the exception: what one writer wrote still verifies."""
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path)
    sink.append(record(1))
    sink.append(record(2))

    with pytest.raises(ConfigurationError):
        FileAuditSink(path)

    sink.append(record(3))
    sink.close()

    head, seq = recover(path)
    assert seq == 3
    assert head
