"""Committed concurrent-load results, and the README rows generated from them.

Item 8 of the external review: the only concurrent figures were prose from a
run nobody kept. A load run is now a committed summary plus locust's raw
CSVs, and the README quotes the newest summary or says plainly that none
exists. The repository test at the bottom holds the README to that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from perf.load import (
    BEGIN,
    END,
    UNRECORDED,
    LoadRecordError,
    block,
    current,
    latest,
    levels,
    replace,
    runs,
    summarise,
)
from perf.scenarios import WARMUP_SECONDS

ROOT = Path(__file__).resolve().parents[3]


def samples(outcome: str, latencies: list[float], *, start: float = 10.0) -> dict[str, Any]:
    return {outcome: [(start + i, ms) for i, ms in enumerate(latencies)]}


def a_run(users: int = 20, **overrides: Any) -> dict[str, Any]:
    run = summarise(
        {**samples("served", [10.0, 20.0, 30.0, 40.0]), **samples("refused", [1.0, 2.0])},
        users_requested=users,
        users_started=users,
        failed_to_start=0,
        throughput=123.4,
    )
    run.update(overrides)
    return run


def a_record(*runs_: dict[str, Any]) -> dict[str, Any]:
    return {
        "recorded": "2026-10-05T12:00:00+00:00",
        "commit": "abcdef0123",
        "dirty": False,
        "flags": "auth=on audit=on",
        "run_seconds": 30,
        "warmup_seconds": WARMUP_SECONDS,
        "machine": {"system": "Darwin", "machine": "arm64"},
        "runs": list(runs_) or [a_run()],
    }


def test_the_summary_excludes_the_warm_up_window_like_the_printed_report() -> None:
    early_and_slow = {"served": [(0.5, 900.0), (20.0, 10.0), (21.0, 12.0)]}

    run = summarise(
        early_and_slow, users_requested=2, users_started=2, failed_to_start=0, throughput=1.0
    )

    assert run["outcomes"]["served"]["p99_ms"] == 12.0, "a cold-start sample reached the p99"
    assert run["outcomes"]["served"]["count"] == 3, "the count still includes it"


def test_an_outcome_with_no_samples_is_absent_not_zero() -> None:
    """A bucket with no requests has no p95; `0 ms` would read as very fast."""
    run = a_run()

    assert "failed" not in run["outcomes"]


def test_a_run_that_lost_users_at_startup_is_refused() -> None:
    """The harness's first version lost half its fleet to a Keycloak lockout and
    printed a confident table anyway."""
    with pytest.raises(LoadRecordError, match="lost 3 user"):
        runs(a_record(a_run(failed_to_start=3)))


def test_a_run_that_started_fewer_users_than_requested_is_refused() -> None:
    """What a dry run with no stack produces: users requested, none started."""
    with pytest.raises(LoadRecordError, match="started 0 of 20"):
        runs(a_record(a_run(users_started=0)))


def test_a_run_that_served_nothing_is_refused() -> None:
    run = summarise(
        samples("refused", [1.0]),
        users_requested=20,
        users_started=20,
        failed_to_start=0,
        throughput=1.0,
    )

    with pytest.raises(LoadRecordError, match="served"):
        runs(a_record(run))


def test_no_summary_renders_the_sentence_that_says_so(tmp_path: Path) -> None:
    assert latest(tmp_path) is None
    assert block(None, root=tmp_path) == f"{BEGIN}\n{UNRECORDED}\n{END}"


def test_the_block_quotes_every_level_in_order_with_its_evidence(tmp_path: Path) -> None:
    path = tmp_path / "perf" / "results" / "load-2026-10-05-abcdef0.json"
    rendered = block((path, a_record(a_run(50), a_run(20))), root=tmp_path)

    twenty = rendered.index("| 20 |")
    fifty = rendered.index("| 50 |")
    assert twenty < fifty
    assert "123 req/s" in rendered
    assert "perf/results/load-2026-10-05-abcdef0/" in rendered, "the raw CSVs are linked"
    assert "`abcdef0`" in rendered
    assert "auth=on audit=on" in rendered


def test_the_newest_summary_by_name_is_the_one_quoted(tmp_path: Path) -> None:
    for name in ("load-2026-10-01-aaaaaaa.json", "load-2026-10-05-bbbbbbb.json"):
        (tmp_path / name).write_text(json.dumps(a_record()), encoding="utf-8")

    found = latest(tmp_path)

    assert found is not None
    assert found[0].name == "load-2026-10-05-bbbbbbb.json"


def test_replace_and_current_need_exactly_one_block() -> None:
    with pytest.raises(LoadRecordError):
        current("no markers here")
    with pytest.raises(LoadRecordError):
        replace(f"{BEGIN}a{END}{BEGIN}b{END}", "x")


def test_levels_must_be_positive_distinct_and_ascending() -> None:
    assert levels((20, 50)) == (20, 50)
    for bad in ((), (0, 20), (50, 20), (20, 20)):
        with pytest.raises(LoadRecordError):
            levels(bad)


def test_the_readme_quotes_the_newest_committed_load_run() -> None:
    """The point of the module. Either the README says no run is recorded and
    none is, or it quotes exactly the newest committed summary."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert current(readme) == block(latest(), root=ROOT)
