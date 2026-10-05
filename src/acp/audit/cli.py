"""`acp audit verify` and `acp audit checkpoint`.

`verify` reports every break; `checkpoint` writes the anchor that lets `verify` detect
truncation and rewrite. Kept out of `acp.cli` (as `acp.secrets.cli` is) so it imports no
MCP SDK and stays testable.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from acp.audit.chain import verify
from acp.audit.checkpoint import Checkpoint, check
from acp.audit.checkpoint import load as load_checkpoint

OK: Final = 0
BROKEN: Final = 1
"""Exit code for a broken chain or failed anchor check, for CI (like `acp schemas check`)."""

MISSING: Final = 2
"""Exit code when the log is missing or empty, so a bad path does not read as tampering."""


@contextmanager
def _lines(path: Path) -> Iterator[Iterator[str]]:
    """Stream a chain's lines."""
    with path.open("r", encoding="utf-8") as handle:
        yield handle


def verify_command(
    log_path: Path,
    *,
    checkpoint_path: Path | None = None,
    out: Callable[[str], None] = print,
) -> int:
    """Verify the chain and its anchor, always printing both results (even with no anchor)."""
    if not log_path.exists():
        out(f"no audit log at {log_path}")
        return MISSING

    anchor = load_checkpoint(checkpoint_path) if checkpoint_path is not None else None

    with _lines(log_path) as stream:
        result = verify(stream, anchor_seq=anchor.seq if anchor else None)

    anchoring = check(anchor, entries=result.entries, anchor_hash=result.anchor_hash)

    out(f"chain:  {result.describe()}")
    out(f"anchor: {anchoring.reason}")

    if not result.intact:
        out("")
        out(
            "A break means the file no longer matches the hashes written with it. "
            "Do not repair it — archive the file as it stands, because the damage "
            "itself is the evidence."
        )
    elif anchor is None:
        out("")
        out(
            "The chain is internally consistent, which is a weaker claim than it "
            "sounds: truncating the end or rewriting from the start both leave a "
            "valid chain. Run `acp audit checkpoint` and commit the result to "
            "make those detectable."
        )

    return OK if (result.intact and anchoring.satisfied) else BROKEN


def checkpoint_command(
    log_path: Path,
    *,
    checkpoint_path: Path,
    out: Callable[[str], None] = print,
    now: Callable[[], float] = time.time,
) -> int:
    """Write a checkpoint at the chain's current end.

    Refuses (returns `BROKEN`, writes nothing) if the chain does not verify, so damage never
    becomes the baseline.
    """
    if not log_path.exists():
        out(f"no audit log at {log_path}")
        return MISSING

    with _lines(log_path) as stream:
        result = verify(stream)

    if not result.intact:
        out(f"chain: {result.describe()}")
        out("")
        out(
            "Refusing to write a checkpoint over a chain that does not verify. "
            "Anchoring it would make this damage the baseline every later check "
            "compares against — the break would be blessed by the tool meant to "
            "find it. Investigate and archive first."
        )
        return BROKEN

    if result.entries == 0:
        out(f"{log_path} has no entries; there is nothing to anchor yet")
        return MISSING

    checkpoint = Checkpoint(seq=result.entries, head=result.head, at=now())
    checkpoint.save(checkpoint_path)

    out(f"checkpoint written to {checkpoint_path}: {checkpoint.describe()}")
    out("")
    out(
        "Commit it. An anchor stored where the log's writer can reach it proves "
        "nothing, because whoever rewrites one rewrites the other — its value is "
        "exactly the distance between it and the log."
    )
    return OK
