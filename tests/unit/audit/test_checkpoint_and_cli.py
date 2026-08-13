"""The anchor, and the two commands that use it — task 57.

An audit log nobody can verify is just an expensive log, which is why this is
its own task. The chain catches edits; the anchor catches the two attacks a
self-contained chain provably cannot see. These are the tests for the second
half.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.audit.chain import Chain, verify
from acp.audit.checkpoint import Checkpoint, check
from acp.audit.checkpoint import load as load_checkpoint
from acp.audit.cli import BROKEN, MISSING, OK, checkpoint_command, verify_command
from acp.audit.record import AuditRecord, Category, Outcome
from acp.exceptions import ConfigurationError


def record(index: int) -> AuditRecord:
    return AuditRecord(
        category=Category.AUTHORIZATION,
        event="policy.decision",
        at=1786600000.0 + index,
        subject="alice",
        tenant="acme",
        tool="mock-a__search",
        outcome=Outcome.DENIED,
    )


def write_chain(path: Path, count: int) -> list[str]:
    chain = Chain()
    lines = [
        json.dumps(chain.append(record(index)).as_dict(), separators=(",", ":"))
        for index in range(count)
    ]
    path.write_text("\n".join(lines) + "\n")
    return lines


class Captured:
    """Collects command output, so a test asserts on what an operator reads."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


# ---------------------------------------------------------------------------
# The anchor
# ---------------------------------------------------------------------------


def test_a_missing_anchor_is_not_an_error(tmp_path: Path) -> None:
    """Every new deployment starts unanchored, and refusing to verify without one
    would make the verifier useless until somebody remembered a step."""
    assert load_checkpoint(tmp_path / "absent.json") is None


def test_a_corrupt_anchor_is_an_error(tmp_path: Path) -> None:
    """**Not treated as missing.** Silently downgrading "the anchor was tampered
    with" to "there is no anchor" is exactly the move an attacker would make."""
    path = tmp_path / "checkpoint.json"
    path.write_text("{ not json")

    with pytest.raises(ConfigurationError, match="not readable JSON"):
        load_checkpoint(path)


def test_an_anchor_missing_its_fields_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text(json.dumps({"seq": 4}))

    with pytest.raises(ConfigurationError, match="seq"):
        load_checkpoint(path)


def test_no_anchor_is_reported_rather_than_passed_silently() -> None:
    """ "Verified against a committed checkpoint" and "verified against nothing"
    are different claims and must never read the same."""
    anchoring = check(None, entries=10, anchor_hash="a" * 64)

    assert anchoring.satisfied
    assert "nothing anchored" in anchoring.reason


def test_the_anchor_catches_truncation(tmp_path: Path) -> None:
    """**The attack the chain cannot see.**"""
    path = tmp_path / "audit.jsonl"
    lines = write_chain(path, 10)
    full = verify(lines, anchor_seq=8)
    anchor = Checkpoint(seq=8, head=full.anchor_hash or "", at=None)

    shortened = verify(lines[:5], anchor_seq=8)

    assert shortened.intact, "a truncated chain still verifies — that is the point"
    assert not check(anchor, entries=shortened.entries, anchor_hash=shortened.anchor_hash).satisfied


def test_the_anchor_catches_a_rewrite(tmp_path: Path) -> None:
    """The other one. An attacker who owns the file rebuilds a clean chain; every
    link is correct and the anchor still says it is the wrong chain."""
    path = tmp_path / "audit.jsonl"
    original = write_chain(path, 6)
    anchor_hash = verify(original, anchor_seq=3).anchor_hash
    anchor = Checkpoint(seq=3, head=anchor_hash or "", at=None)

    forged_path = tmp_path / "forged.jsonl"
    forged = write_chain(forged_path, 6)
    # Same length, same shape, different content at entry 3.
    forged_result = verify(forged, anchor_seq=3)

    assert forged_result.intact
    outcome = check(anchor, entries=forged_result.entries, anchor_hash=forged_result.anchor_hash)
    # The forged chain here is byte-identical because the records are, which is
    # itself the honest caveat: a rewrite is only detectable when it *changes*
    # something. Change one record and the anchor fires.
    tampered = json.loads(forged[2])
    tampered["record"]["outcome"] = "allowed"
    forged[2] = json.dumps(tampered, separators=(",", ":"))
    rebuilt = Chain()
    rechained = [
        json.dumps(rebuilt.append(json.loads(line)["record"]).as_dict(), separators=(",", ":"))
        for line in forged
    ]
    after = verify(rechained, anchor_seq=3)

    assert outcome.satisfied, "an unchanged rewrite is by definition the same chain"
    assert after.intact, "the attacker's chain links correctly"
    assert not check(anchor, entries=after.entries, anchor_hash=after.anchor_hash).satisfied


# ---------------------------------------------------------------------------
# acp audit verify
# ---------------------------------------------------------------------------


def test_verify_reports_an_intact_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_chain(path, 4)
    out = Captured()

    assert verify_command(path, out=out) == OK
    assert "chain intact" in out.text


def test_verify_exits_non_zero_on_a_break(tmp_path: Path) -> None:
    """So it composes with CI and cron without anybody parsing its output."""
    path = tmp_path / "audit.jsonl"
    lines = write_chain(path, 4)
    payload = json.loads(lines[1])
    payload["record"]["subject"] = "mallory"
    lines[1] = json.dumps(payload, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    out = Captured()

    assert verify_command(path, out=out) == BROKEN
    assert "entry 2" in out.text


def test_verify_tells_you_not_to_repair_it(tmp_path: Path) -> None:
    """The damage is the evidence. An operator's first instinct is to make the
    tool go green, and the tool should say why that is the wrong instinct."""
    path = tmp_path / "audit.jsonl"
    path.write_text("garbage\n")
    out = Captured()

    verify_command(path, out=out)

    assert "Do not repair" in out.text


def test_a_missing_log_is_distinct_from_a_broken_one(tmp_path: Path) -> None:
    """Folding them together means a misconfigured path reads as tampering."""
    out = Captured()

    assert verify_command(tmp_path / "absent.jsonl", out=out) == MISSING


def test_verify_says_when_it_checked_no_anchor(tmp_path: Path) -> None:
    """Internal consistency is a weaker claim than it sounds, and the command
    says so rather than letting a green tick imply more."""
    path = tmp_path / "audit.jsonl"
    write_chain(path, 3)
    out = Captured()

    verify_command(path, checkpoint_path=tmp_path / "absent.json", out=out)

    assert "weaker claim" in out.text


def test_verify_fails_when_the_chain_no_longer_reaches_its_anchor(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    anchor_path = tmp_path / "checkpoint.json"
    lines = write_chain(path, 10)
    assert checkpoint_command(path, checkpoint_path=anchor_path, out=Captured()) == OK

    path.write_text("\n".join(lines[:4]) + "\n")
    out = Captured()

    assert verify_command(path, checkpoint_path=anchor_path, out=out) == BROKEN
    assert "removed from the end" in out.text


# ---------------------------------------------------------------------------
# acp audit checkpoint
# ---------------------------------------------------------------------------


def test_checkpoint_records_the_current_head(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    anchor_path = tmp_path / "checkpoint.json"
    write_chain(path, 7)

    assert checkpoint_command(path, checkpoint_path=anchor_path, out=Captured()) == OK

    anchor = load_checkpoint(anchor_path)
    assert anchor is not None
    assert anchor.seq == 7


def test_checkpoint_refuses_a_broken_chain(tmp_path: Path) -> None:
    """**Anchoring damage would launder it.** Every later verification would
    compare against a state that already contained the break, and the tool built
    to find it would have blessed it."""
    path = tmp_path / "audit.jsonl"
    anchor_path = tmp_path / "checkpoint.json"
    lines = write_chain(path, 4)
    payload = json.loads(lines[1])
    payload["record"]["subject"] = "mallory"
    lines[1] = json.dumps(payload, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    out = Captured()

    assert checkpoint_command(path, checkpoint_path=anchor_path, out=out) == BROKEN
    assert not anchor_path.exists()
    assert "blessed by the tool" in out.text


def test_checkpoint_tells_you_where_to_put_it(tmp_path: Path) -> None:
    """An anchor stored where the log's writer can reach it proves nothing. The
    command says so, because the whole value is the distance between the two and
    nothing in the code can enforce it."""
    path = tmp_path / "audit.jsonl"
    write_chain(path, 3)
    out = Captured()

    checkpoint_command(path, checkpoint_path=tmp_path / "checkpoint.json", out=out)

    assert "Commit it" in out.text


def test_checkpoint_will_not_anchor_an_empty_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("")

    assert checkpoint_command(path, checkpoint_path=tmp_path / "c.json", out=Captured()) == MISSING


def test_a_fresh_checkpoint_verifies(tmp_path: Path) -> None:
    """The round trip: anchor a chain, then verify against that anchor."""
    path = tmp_path / "audit.jsonl"
    anchor_path = tmp_path / "checkpoint.json"
    write_chain(path, 5)
    checkpoint_command(path, checkpoint_path=anchor_path, out=Captured())
    out = Captured()

    assert verify_command(path, checkpoint_path=anchor_path, out=out) == OK
    assert "reaches the checkpoint" in out.text
