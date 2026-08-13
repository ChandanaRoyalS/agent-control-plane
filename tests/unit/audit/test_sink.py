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


def test_a_failed_write_leaves_no_gap(tmp_path: Path) -> None:
    """The sequence number is reused on the next attempt.

    A skipped number is indistinguishable from a deletion to anybody reading the
    chain later, so a write that fails must not consume one — otherwise a
    transient disk error is permanently recorded as evidence of tampering.
    """
    path = tmp_path / "audit.jsonl"
    sink = sink_at(path)
    sink.append(record(0))

    class Broken:
        def write(self, _text: str) -> int:
            raise OSError("no space left on device")

        def flush(self) -> None:  # pragma: no cover — never reached
            pass

    working = sink._handle
    sink._handle = Broken()  # type: ignore[assignment]
    with pytest.raises(OSError, match="no space"):
        sink.append(record(1))

    sink._handle = working
    entry = sink.append(record(1))
    sink.close()

    assert entry.seq == 2
    assert verify(path.read_text().splitlines()).intact


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
