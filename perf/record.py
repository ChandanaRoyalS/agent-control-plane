"""Overhead results as committed files, and the README rows that quote them.

`scripts/measure_overhead.py` prints what the gateway adds over a direct call,
with the switch settings that produced it (ADR 0054). Until now the README
quoted those numbers by hand, from an ADR, with no file anyone could check them
against. This module closes that gap the way `docs/surface.json` and
`corpus/eval-baseline.json` closed theirs:

- `scripts/record_overhead.py` runs the harness and writes
  `perf/results/overhead-<date>-<commit>.json` — the measurement, the switch
  settings, the commit it ran against, whether the tree was dirty, and the
  machine;
- the README's overhead rows are **generated** from the newest file, between
  two markers, and a test fails when they disagree.

So a number in the README is always the number in a committed file, and a
reader can see exactly which run, on which machine, at which commit, under
which configuration.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from perf.overhead import Overhead, decode

RESULTS: Final = Path(__file__).resolve().parent / "results"
PREFIX: Final = "overhead-"
BEGIN: Final = "<!-- overhead:begin -->"
END: Final = "<!-- overhead:end -->"
ROWS: Final = ("cache miss", "cache hit")
"""The rows the README quotes, in order. A record missing one is refused rather
than rendered with a hole."""


class RecordError(ValueError):
    """A results file or README that cannot be rendered or checked."""


def latest(directory: Path = RESULTS) -> tuple[Path, dict[str, Any]]:
    """The newest record by file name, which starts with its date."""
    files = sorted(directory.glob(f"{PREFIX}*.json"))
    if not files:
        msg = (
            f"no overhead results in {directory}. Record one: "
            f"`make up && make overhead-record`, then commit the file it writes."
        )
        raise RecordError(msg)
    path = files[-1]
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"cannot read {path.name}: {exc}"
        raise RecordError(msg) from exc
    if not isinstance(record, dict):
        msg = f"{path.name}: expected a JSON object"
        raise RecordError(msg)
    return path, record


def rows(record: Mapping[str, Any]) -> dict[str, Overhead]:
    """The measured rows by label, with every row the README quotes present."""
    try:
        _, decoded = decode(record["measurement"])
    except (KeyError, TypeError, ValueError) as exc:
        msg = f"record has no readable measurement: {exc}"
        raise RecordError(msg) from exc
    by_label = dict(decoded)
    missing = [label for label in ROWS if label not in by_label]
    if missing:
        msg = f"record is missing row(s): {', '.join(missing)}"
        raise RecordError(msg)
    return by_label


def block(path: Path, record: Mapping[str, Any], *, root: Path) -> str:
    """The README text between the markers, rendered from one record."""
    measured = rows(record)
    machine = record.get("machine", {})
    where = " ".join(str(part) for part in (machine.get("system"), machine.get("machine")) if part)
    when = str(record.get("recorded", "?"))[:10]
    link = path.relative_to(root).as_posix()
    lines = [
        BEGIN,
        "| gateway overhead | p50 | added at p95 | recorded |",
        "|---|---|---|---|",
    ]
    for label in ROWS:
        result = measured[label]
        lines.append(
            f"| {label} | {result.multiple:.1f}x a direct call "
            f"({result.added[50]:+.0f} ms) | {result.added[95]:+.0f} ms | "
            f"[{when}, {where}]({link}) |"
        )
    flags = record.get("measurement", {}).get("flags", "")
    commit = str(record.get("commit", "?"))[:7]
    dirty = " (uncommitted changes)" if record.get("dirty") else ""
    lines.extend(
        [
            "",
            f"Sequential, one request in flight, mock upstreams; commit `{commit}`{dirty}; "
            f"switches `{flags}`.",
            END,
        ]
    )
    return "\n".join(lines)


_BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)


def replace(text: str, rendered: str) -> str:
    """``text`` with its overhead block swapped for ``rendered``."""
    if len(_BLOCK.findall(text)) != 1:
        msg = f"expected exactly one {BEGIN} ... {END} block"
        raise RecordError(msg)
    return _BLOCK.sub(lambda _: rendered, text)


def current(text: str) -> str:
    """The overhead block as it stands in ``text``."""
    found = _BLOCK.findall(text)
    if len(found) != 1:
        msg = f"expected exactly one {BEGIN} ... {END} block"
        raise RecordError(msg)
    return str(found[0])
