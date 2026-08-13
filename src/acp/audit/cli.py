"""`acp audit verify` and `acp audit checkpoint` — task 57.

**An audit log nobody can verify is just an expensive log**, which is the whole
justification for this task existing as its own line in the plan. The chain is
worth exactly as much as the ease of checking it: a verification that requires
writing a script is one that happens after an incident, and the point of
tamper-evidence is to notice *before* anybody is looking for a reason to.

The decisions live here rather than in `acp.cli`, following `acp.secrets.cli`.
That module says why, and it is worth repeating: `acp.cli` imports the MCP SDK,
so anything written there cannot be tested or type-checked in the environment it
is authored in — which is how three bugs shipped. This file has no SDK import,
no gateway import, and no network. It reads a file and compares hashes.

**Two verbs, and the second one is the interesting one.**

`verify` walks the chain and reports every break. `checkpoint` writes the anchor
that makes `verify` able to detect truncation and wholesale rewrite — the two
attacks a self-contained chain provably cannot see (`acp.audit.chain` sets out
which is which). Committing that anchor is the act that turns "these entries are
consistent with each other" into "these entries are the ones that were written".
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
"""Non-zero on a broken chain, so `acp audit verify` composes with CI and cron
without anybody parsing its output. The same shape as `acp schemas check`."""

MISSING: Final = 2
"""The log is not there at all. Distinct from `BROKEN` on purpose: a chain that
fails to verify and a chain that does not exist are different incidents, and
folding them together means a misconfigured path reads as tampering."""


@contextmanager
def _lines(path: Path) -> Iterator[Iterator[str]]:
    """Stream a chain, so verifying one larger than memory costs nothing extra."""
    with path.open("r", encoding="utf-8") as handle:
        yield handle


def verify_command(
    log_path: Path,
    *,
    checkpoint_path: Path | None = None,
    out: Callable[[str], None] = print,
) -> int:
    """Walk the chain, compare it against its anchor, and report.

    Both halves always run and both are always printed, including when there is
    no anchor to check. "Verified against a committed checkpoint" and "verified
    against nothing" must never read the same in a build log — the second is a
    considerably weaker statement, and the difference is invisible unless it is
    said out loud.
    """
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
    """Record where the chain has got to, for a later verification to anchor on.

    **Refuses to anchor a broken chain.** Writing a checkpoint over a chain that
    does not verify would launder the damage: every future verification would
    compare against a state that already contained it, and the break would have
    been blessed by the tool built to find it. So this verifies first and exits
    non-zero without writing.

    The anchor is taken at the chain's current end. That is the strongest
    position available — everything before it becomes fixed — and it is why the
    command is worth running on a schedule rather than once.
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
