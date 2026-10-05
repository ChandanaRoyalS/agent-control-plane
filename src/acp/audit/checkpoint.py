"""External anchor for the audit chain, which cannot detect tail truncation or rewrite alone.

`acp audit checkpoint` records a (seq, hash) pair; `acp audit verify --checkpoint` fails if
the chain no longer reaches it, the committed-baseline pattern of ADR 0013. The anchor only
helps if stored where the log's writer cannot reach it; code cannot enforce that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from acp.exceptions import ConfigurationError

DEFAULT_CHECKPOINT_PATH: Final = Path("config/audit-checkpoint.json")
"""Under `config/`, committed and mounted read-only (ADR 0014), so the gateway cannot rewrite it."""


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A chain position (seq and head hash), small enough to paste anywhere."""

    seq: int
    head: str

    at: float | None = None
    """When it was taken; informational, not part of the anchor."""

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "head": self.head, "at": self.at}

    def describe(self) -> str:
        return f"entry {self.seq}, head {self.head[:16]}…"

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n")


def load(path: Path) -> Checkpoint | None:
    """The committed anchor, or ``None`` if the file does not exist.

    Raises:
        ConfigurationError: The file exists but is corrupt; treating that as absent would
            let tampering downgrade to "no anchor".
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
        """True when there was no checkpoint (reported, not failed) or the check passed."""
        return self.checkpoint is None or self.reached


def check(checkpoint: Checkpoint | None, *, entries: int, anchor_hash: str | None) -> Anchoring:
    """Whether the chain still holds the anchored entry with the anchored hash.

    Compares that entry rather than the final head, so an older checkpoint still detects a
    later rewrite.
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
