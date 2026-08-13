"""What the chain proves, and the two attacks it provably cannot see.

Task 56. Every test here is an attack, because "tamper-evident" is only worth
what an attempt at tampering costs — and the two that *pass* are the most
important assertions in the file. A chain that detected everything would be a
chain whose claims nobody had checked.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from acp.audit.chain import GENESIS, Chain, link, verify
from acp.audit.record import AUDIT_VERSION, AuditRecord, Category, Outcome, canonical


def record(index: int, outcome: Outcome = Outcome.DENIED) -> AuditRecord:
    return AuditRecord(
        category=Category.AUTHORIZATION,
        event="policy.decision",
        at=1786600000.0 + index,
        subject="alice@example.test",
        actor="agent-1",
        tenant="acme",
        tool="mock-a__search",
        rule="deny-search",
        outcome=outcome,
        detail={"argument_names": ["query"]},
    )


def chain_of(count: int) -> list[str]:
    """A written chain, as lines, exactly as `FileAuditSink` would write them."""
    chain = Chain()
    return [
        json.dumps(chain.append(record(index)).as_dict(), separators=(",", ":"))
        for index in range(count)
    ]


# ---------------------------------------------------------------------------
# The link
# ---------------------------------------------------------------------------


def test_the_first_entry_links_to_genesis() -> None:
    """A fixed, obviously-not-a-hash predecessor, so "this is the start" is a
    claim the format states rather than one a reader infers from an absence."""
    entry = Chain().append(record(0))

    assert entry.prev == GENESIS
    assert entry.seq == 1


def test_the_same_record_at_a_different_position_hashes_differently() -> None:
    """The sequence number is inside the hash, so entries cannot be renumbered
    to hide a removal."""
    payload = record(0).as_dict()

    assert link(prev=GENESIS, seq=1, payload=payload) != link(prev=GENESIS, seq=2, payload=payload)


def test_the_same_record_after_a_different_predecessor_hashes_differently() -> None:
    first, second = chain_of(2), chain_of(2)
    assert json.loads(first[1])["hash"] == json.loads(second[1])["hash"]

    moved = Chain(head="a" * 64, seq=0).append(record(0))
    assert moved.hash != json.loads(first[0])["hash"]


def test_the_version_participates_in_the_link() -> None:
    """So a chain written under one rule cannot be verified under another and
    silently pass.

    Asserted by recomputing the documented construction rather than by reloading
    the module: this pins *both* that `link` hashes what its docstring says it
    hashes, and that changing the stamp changes the answer. A test that only
    checked the second could pass over an implementation that ignored three of
    the four inputs.
    """
    payload = record(0).as_dict()

    def digest(version: str) -> str:
        material = canonical(
            {"v": version, "prev": GENESIS, "seq": 1, "record": canonical(payload)}
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    assert link(prev=GENESIS, seq=1, payload=payload) == digest(AUDIT_VERSION)
    assert digest(AUDIT_VERSION) != digest("acp-audit-v2")


# ---------------------------------------------------------------------------
# What it catches
# ---------------------------------------------------------------------------


def test_an_untouched_chain_verifies() -> None:
    result = verify(chain_of(6))

    assert result.intact
    assert result.entries == 6


def test_an_edited_record_is_caught() -> None:
    lines = chain_of(6)
    payload = json.loads(lines[2])
    payload["record"]["outcome"] = "allowed"
    lines[2] = json.dumps(payload, separators=(",", ":"))

    result = verify(lines)

    assert not result.intact
    assert [b.seq for b in result.breaks] == [3]


def test_one_edit_produces_one_break_not_a_cascade() -> None:
    """**The reason `verify` continues from what the file claims.**

    Re-deriving the head after a mismatch would make a single edit break every
    entry after it, burying the location of the actual change under thousands of
    consequences. An investigator needs the line number, not the blast radius.
    """
    lines = chain_of(50)
    payload = json.loads(lines[10])
    payload["record"]["subject"] = "mallory"
    lines[10] = json.dumps(payload, separators=(",", ":"))

    assert len(verify(lines).breaks) == 1


def test_a_removed_entry_is_caught() -> None:
    lines = chain_of(6)
    spliced = lines[:2] + lines[3:]

    result = verify(spliced)

    assert not result.intact
    reasons = " ".join(b.reason for b in result.breaks)
    assert "sequence jumped" in reasons
    assert "prev does not match" in reasons


def test_reordered_entries_are_caught() -> None:
    lines = chain_of(6)
    swapped = [*lines[:1], lines[2], lines[1], *lines[3:]]

    assert not verify(swapped).intact


def test_an_unreadable_line_is_a_failure_not_a_skip() -> None:
    """The opposite call from the decision-log reader (ADR 0045), for the
    opposite reason. That one skips a bad line so a simulator can still answer;
    a line this cannot read is a line whose contribution it cannot check, and
    reporting "verified" over a hole is the lie the chain exists to prevent."""
    lines = chain_of(3)
    lines.insert(1, "{not json")

    result = verify(lines)

    assert result.unreadable == 1
    assert not result.intact


def test_a_line_that_is_json_but_not_an_entry_is_a_failure() -> None:
    lines = chain_of(3)
    lines.insert(1, json.dumps({"hello": "world"}))

    assert not verify(lines).intact


def test_a_sequence_that_arrived_as_a_string_is_not_an_entry() -> None:
    """Types are checked rather than coerced. A hand-edited `"seq": "2"` must not
    walk past the check by being helpfully converted."""
    lines = chain_of(2)
    payload = json.loads(lines[1])
    payload["seq"] = str(payload["seq"])
    lines[1] = json.dumps(payload, separators=(",", ":"))

    assert not verify(lines).intact


def test_a_break_names_the_entry_and_the_line() -> None:
    """ "The chain is broken" makes somebody read the whole file. "Entry 3, line
    3" gives them a time window."""
    lines = chain_of(4)
    payload = json.loads(lines[2])
    payload["record"]["tool"] = "something-else"
    lines[2] = json.dumps(payload, separators=(",", ":"))

    [broken] = verify(lines).breaks

    assert broken.seq == 3
    assert broken.line == 3
    assert "entry 3" in broken.describe()


# ---------------------------------------------------------------------------
# What it provably cannot catch — the honest half
# ---------------------------------------------------------------------------


def test_truncating_the_tail_leaves_a_valid_chain() -> None:
    """**Not a bug. The claim.**

    Delete the last entries and what remains is a chain that verifies, because
    the file no longer contains the evidence that anything followed. Answered by
    `acp.audit.checkpoint`, and asserted here so nobody reads the chain as
    proving more than it does.
    """
    lines = chain_of(10)

    assert verify(lines[:4]).intact


def test_a_chain_rebuilt_from_genesis_verifies() -> None:
    """The other one. An attacker who owns the file and knows the scheme can
    write a clean chain of whatever they like — every link correct, every
    sequence number in order, and nothing inside the file to contradict it."""
    forged = chain_of(6)

    assert verify(forged).intact


def test_the_head_is_what_distinguishes_them() -> None:
    """Which is exactly why the anchor is a head plus a sequence number, and why
    it has to live somewhere the writer cannot reach."""
    full = verify(chain_of(10))
    truncated = verify(chain_of(10)[:4])

    assert full.head != truncated.head


# ---------------------------------------------------------------------------
# The anchor hook
# ---------------------------------------------------------------------------


def test_the_anchor_hash_is_captured_during_the_walk() -> None:
    """Captured, not collected: verifying a chain costs O(1) memory however long
    it is, so the file that matters most is not the one nobody dares verify."""
    lines = chain_of(10)

    result = verify(lines, anchor_seq=4)

    assert result.anchor_hash == json.loads(lines[3])["hash"]


def test_no_anchor_asked_for_means_none_captured() -> None:
    assert verify(chain_of(3)).anchor_hash is None


@pytest.mark.parametrize("count", [0, 1, 2, 40])
def test_length_matches_what_was_written(count: int) -> None:
    assert verify(chain_of(count)).entries == count
