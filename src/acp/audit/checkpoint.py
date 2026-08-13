"""The anchor a chain cannot provide for itself.

Task 57's other half. `acp.audit.chain` is explicit that a hash chain detects
modification, splicing and reordering, and **cannot** detect truncation of the
tail — delete the last thousand entries and what remains is a perfectly valid
chain. Nothing inside the file can say otherwise, because the file no longer
contains the evidence.

The answer is the pattern this project already uses for schema drift (ADR 0013):
**commit the expected state, and compare against it.** `acp audit checkpoint`
records where the chain had got to; `acp audit verify --checkpoint` fails if the
chain no longer reaches it. A truncation that removes the checkpointed entry is
then a build failure rather than a silence.

**Where the anchor lives is the whole security property.** A checkpoint sitting
beside the log, writable by whoever can write the log, proves nothing — an
attacker rewrites both. It is useful exactly to the extent that it is somewhere
the writer cannot reach: committed to the repository, sent to a monitoring
system, printed into a chat channel, read aloud in a meeting. This module makes
the anchor small enough to travel that way — a sequence number and a hash — and
says out loud that *storing it next to the log is a decorative use of it*.

That is a deployment property, not something code here can enforce, which is why
it is stated rather than implemented.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from acp.exceptions import ConfigurationError

DEFAULT_CHECKPOINT_PATH: Final = Path("config/audit-checkpoint.json")
"""Under `config/` because that directory is committed and mounted read-only in
the container (ADR 0014) — so the running gateway cannot rewrite the anchor that
proves it has not rewritten its own log."""


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A position in a chain, small enough to travel by hand.

    Two fields and nothing else. An anchor that needs a parser is an anchor
    nobody pastes into an incident channel, and the whole value of this thing is
    that it can live somewhere the log cannot.
    """

    seq: int
    head: str

    at: float | None = None
    """When it was taken. Not part of the claim — the pair above is — but the
    first thing anybody asks of an anchor is how stale it is."""

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "head": self.head, "at": self.at}

    def describe(self) -> str:
        return f"entry {self.seq}, head {self.head[:16]}…"

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n")


def load(path: Path) -> Checkpoint | None:
    """The committed anchor, or ``None`` when there is not one yet.

    Absence is not an error. Every new deployment starts unanchored, and refusing
    to verify without a checkpoint would mean the verifier is useless until
    somebody remembers a step — so `verify` runs, reports the chain intact, and
    says plainly that it checked no anchor. A corrupt one *is* an error, because
    silently treating it as absent would turn "the anchor was tampered with" into
    "there is no anchor", which is the same downgrade an attacker would choose.
    """
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        msg = f"audit checkpoint at {path} is not readable JSON: {exc}"
        raise ConfigurationError(msg) from exc

    if not isinstance(payload, dict):
        msg = f"audit checkpoint at {path} is not an object"
        raise ConfigurationError(msg)
    seq, head = payload.get("seq"), payload.get("head")
    if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(head, str) or not head:
        msg = f"audit checkpoint at {path} is missing a valid `seq` and `head`"
        raise ConfigurationError(msg)
    at = payload.get("at")
    return Checkpoint(seq=seq, head=head, at=at if isinstance(at, (int, float)) else None)


@dataclass(frozen=True, slots=True)
class Anchoring:
    """Whether a verified chain still reaches its committed anchor."""

    checkpoint: Checkpoint | None
    reached: bool
    reason: str

    @property
    def satisfied(self) -> bool:
        """True when there was nothing to check, or the check passed.

        No checkpoint is *not* a failure — see `load`. It is reported, so that
        "verified against an anchor" and "verified against nothing" never read
        the same in a build log.
        """
        return self.checkpoint is None or self.reached


def check(checkpoint: Checkpoint | None, *, entries: int, anchor_hash: str | None) -> Anchoring:
    """Does this chain still contain the entry the anchor names?

    Checked by looking the sequence number up and comparing hashes, rather than
    by trusting the chain's final head. A chain can be rewritten from any point,
    so "the head is what I expected" is only meaningful for an anchor taken at
    the very end. Anchoring on the *entry* means a checkpoint taken last Tuesday
    still detects a rewrite that happened on Wednesday.
    """
    if checkpoint is None:
        return Anchoring(None, reached=False, reason="no checkpoint committed — nothing anchored")

    if entries < checkpoint.seq:
        return Anchoring(
            checkpoint,
            reached=False,
            reason=(
                f"the chain now ends at entry {entries}, before the checkpointed "
                f"entry {checkpoint.seq} — entries have been removed from the end"
            ),
        )

    found = anchor_hash
    if found is None:
        return Anchoring(
            checkpoint,
            reached=False,
            reason=f"entry {checkpoint.seq} is not present in this chain",
        )
    if found != checkpoint.head:
        return Anchoring(
            checkpoint,
            reached=False,
            reason=(
                f"entry {checkpoint.seq} hashes to {found[:16]}… but the checkpoint "
                f"records {checkpoint.head[:16]}… — the chain was rewritten at or "
                f"before that point"
            ),
        )
    return Anchoring(
        checkpoint, reached=True, reason=f"chain reaches the checkpoint at {checkpoint.describe()}"
    )
