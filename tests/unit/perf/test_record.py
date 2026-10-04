"""Committed overhead results, and the README rows generated from them.

The repository test at the bottom is the point: the README's overhead figures
are whatever the newest file in `perf/results/` says, or the build fails. The
rest pins the rendering and the refusals that keep a broken record from being
quoted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from perf.overhead import Overhead, encode
from perf.record import (
    BEGIN,
    END,
    RESULTS,
    RecordError,
    block,
    current,
    latest,
    replace,
    rows,
)

ROOT = Path(__file__).resolve().parents[3]


def record(**overrides: Any) -> dict[str, Any]:
    def row(gateway: float) -> Overhead:
        return Overhead(
            tool="mock-a__search",
            samples=150,
            gateway={50: gateway, 95: gateway + 10, 99: gateway + 20},
            direct={50: 4.0, 95: 6.0, 99: 8.0},
        )

    base: dict[str, Any] = {
        "recorded": "2026-10-05T10:00:00+00:00",
        "commit": "abcdef1234",
        "dirty": False,
        "machine": {"system": "Darwin", "machine": "arm64"},
        "measurement": encode("audit=on", [("cache miss", row(28.0)), ("cache hit", row(12.0))]),
    }
    base.update(overrides)
    return base


def write(directory: Path, name: str, payload: object) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_the_newest_file_by_date_is_the_one_quoted(tmp_path: Path) -> None:
    write(tmp_path, "overhead-2026-01-01-aaaaaaa.json", record(commit="old"))
    write(tmp_path, "overhead-2026-10-05-bbbbbbb.json", record(commit="new"))
    path, found = latest(tmp_path)
    assert path.name.startswith("overhead-2026-10-05")
    assert found["commit"] == "new"


def test_no_results_is_an_instructive_error(tmp_path: Path) -> None:
    with pytest.raises(RecordError, match="make overhead-record"):
        latest(tmp_path)


def test_an_unreadable_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "overhead-2026-10-05-x.json").write_text("{nope", encoding="utf-8")
    with pytest.raises(RecordError, match="cannot read"):
        latest(tmp_path)
    (tmp_path / "overhead-2026-10-05-x.json").write_text("[1]", encoding="utf-8")
    with pytest.raises(RecordError, match="JSON object"):
        latest(tmp_path)


def test_a_record_missing_a_quoted_row_is_refused() -> None:
    partial = record()
    partial["measurement"]["rows"] = partial["measurement"]["rows"][:1]
    with pytest.raises(RecordError, match="cache hit"):
        rows(partial)
    with pytest.raises(RecordError, match="no readable measurement"):
        rows({"measurement": None})


def test_the_block_quotes_multiple_added_time_machine_commit_and_switches(
    tmp_path: Path,
) -> None:
    path = write(tmp_path, "overhead-2026-10-05-abcdef1.json", record(dirty=True))
    rendered = block(path, record(dirty=True), root=tmp_path)
    assert rendered.startswith(BEGIN)
    assert rendered.endswith(END)
    assert "| cache miss | 7.0x a direct call (+24 ms) | +32 ms |" in rendered
    assert "| cache hit | 3.0x a direct call (+8 ms) | +16 ms |" in rendered
    assert "[2026-10-05, Darwin arm64](overhead-2026-10-05-abcdef1.json)" in rendered
    assert "commit `abcdef1` (uncommitted changes)" in rendered
    assert "switches `audit=on`" in rendered


def test_replace_and_current_need_exactly_one_block() -> None:
    text = f"before\n{BEGIN}\nold\n{END}\nafter\n"
    assert replace(text, f"{BEGIN}\nnew\n{END}") == f"before\n{BEGIN}\nnew\n{END}\nafter\n"
    assert current(text) == f"{BEGIN}\nold\n{END}"
    for broken in ("no markers", text + text):
        with pytest.raises(RecordError, match="exactly one"):
            replace(broken, "x")
        with pytest.raises(RecordError, match="exactly one"):
            current(broken)


def test_the_readme_quotes_the_newest_committed_result() -> None:
    """The README's overhead rows are generated from a committed run, never
    typed. If this fails, `uv run python scripts/record_overhead.py --render`."""
    path, newest = latest(RESULTS)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert current(readme) == block(path, newest, root=ROOT)
