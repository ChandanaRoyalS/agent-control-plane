"""Concurrent-load results as committed files, and the README rows that quote them.

The overhead record (`perf.record`) answers "what does one call cost through
the gateway", sequentially, one request in flight. The external review's
item 8 asked the other question: what happens with 20 and 50 agents at once,
and where is the raw output? Until now the only concurrent figures were the
ADR 0053 before/after, reported in prose from a run nobody kept.

So the load test gets the overhead record's treatment:

- `scripts/record_load.py` runs the locust harness at each concurrency level,
  keeps **locust's raw CSVs** under `perf/results/load-<date>-<commit>/`, and
  writes a summary `perf/results/load-<date>-<commit>.json` with the
  per-outcome percentiles, the switch settings read from the running
  container, the commit, whether the tree was dirty, and the machine;
- the README's load rows are **generated** from the newest summary between two
  markers, and a test fails when they disagree.

Before any run is recorded the block says so in words. A test also fails if a
summary exists and the README still says "not yet recorded".
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from perf.scenarios import Outcome, after_warmup, percentiles

RESULTS: Final = Path(__file__).resolve().parent / "results"
PREFIX: Final = "load-"
BEGIN: Final = "<!-- load:begin -->"
END: Final = "<!-- load:end -->"
LEVELS: Final = (20, 50)
"""Concurrent users per recorded run: the review asked for 20 to 50."""
RUN_SECONDS: Final = 30
UNRECORDED: Final = "No concurrent run has been recorded yet: `make up && make load-record`."
DISQUALIFYING: Final = ("throttled", "upstream", "unrecorded", "failed")
"""Outcomes that mean a run measured something other than the gateway: the rate
limiter or quota, a mock that could not keep up, an audit sink that could not,
or a defect. The harness already warns on each; the recorder refuses them."""
BUDGETS_OFF: Final = {"ACP_RATE_LIMIT_ENABLED": "false", "ACP_QUOTA_ENABLED": "false"}
"""How the recorder runs the gateway. The compose stack's budgets are sized for
a demo, and 20 agents at up to 30 requests a second each exceed them, so a run
with them on measures the limiter. Switched off for the run, said so in the
switches line, and restored afterwards."""


class LoadRecordError(ValueError):
    """A summary or README that cannot be rendered or checked."""


def summarise(
    samples: Mapping[str, list[tuple[float, float]]],
    *,
    users_requested: int | None,
    users_started: int,
    failed_to_start: int,
    throughput: float,
) -> dict[str, Any]:
    """One run, as the summary file stores it.

    Percentiles exclude the warm-up window, exactly as the printed report does,
    so the file and the terminal cannot disagree about the same run.
    """
    total = sum(len(v) for v in samples.values())
    outcomes: dict[str, dict[str, float | int]] = {}
    for outcome in Outcome:
        taken = samples.get(outcome.value, [])
        if not taken:
            continue
        marks = percentiles(after_warmup(taken))
        outcomes[outcome.value] = {
            "count": len(taken),
            "share": round(len(taken) / total, 4) if total else 0.0,
            "p50_ms": round(marks.get(50, 0.0), 1),
            "p95_ms": round(marks.get(95, 0.0), 1),
            "p99_ms": round(marks.get(99, 0.0), 1),
        }
    return {
        "users_requested": users_requested,
        "users_started": users_started,
        "failed_to_start": failed_to_start,
        "requests": total,
        "throughput_rps": round(throughput, 1),
        "outcomes": outcomes,
    }


def runs(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The recorded runs, refusing one the README could not honestly quote."""
    found = record.get("runs")
    if not isinstance(found, list) or not found:
        msg = "record has no runs"
        raise LoadRecordError(msg)
    for run in found:
        if not isinstance(run, Mapping) or "served" not in run.get("outcomes", {}):
            msg = "a run has no `served` outcome: it measured nothing a caller receives"
            raise LoadRecordError(msg)
        requested, started = run.get("users_requested"), run.get("users_started")
        if requested and started != requested:
            msg = (
                f"a run started {started} of {requested} users; its concurrency is not "
                f"the one it claims. Is the stack up and Keycloak reachable? Re-record."
            )
            raise LoadRecordError(msg)
        bad = {o: run["outcomes"][o]["count"] for o in DISQUALIFYING if o in run["outcomes"]}
        if bad:
            what = "the rate limiter" if "throttled" in bad else "something other than the gateway"
            msg = (
                f"a run at {requested} users had {bad}: it measured {what}, "
                f"not the request path. Nothing was written."
            )
            raise LoadRecordError(msg)
        if run.get("failed_to_start"):
            msg = (
                f"a run lost {run['failed_to_start']} user(s) at startup; its concurrency "
                f"is not the one it claims. Re-record."
            )
            raise LoadRecordError(msg)
    return list(found)


def latest(directory: Path = RESULTS) -> tuple[Path, dict[str, Any]] | None:
    """The newest summary by file name, or ``None`` when none is recorded."""
    files = sorted(directory.glob(f"{PREFIX}*.json"))
    if not files:
        return None
    path = files[-1]
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"cannot read {path.name}: {exc}"
        raise LoadRecordError(msg) from exc
    if not isinstance(record, dict):
        msg = f"{path.name}: expected a JSON object"
        raise LoadRecordError(msg)
    return path, record


def _cell(run: Mapping[str, Any], outcome: str, mark: str) -> str:
    found = run["outcomes"].get(outcome)
    return f"{found[mark]:.0f} ms" if found else "—"


def block(found: tuple[Path, Mapping[str, Any]] | None, *, root: Path) -> str:
    """The README text between the markers: the newest record, or the sentence
    that says there is none."""
    if found is None:
        return "\n".join([BEGIN, UNRECORDED, END])
    path, record = found
    recorded = runs(record)
    machine = record.get("machine", {})
    where = " ".join(str(p) for p in (machine.get("system"), machine.get("machine")) if p)
    when = str(record.get("recorded", "?"))[:10]
    raw = path.with_suffix("").relative_to(root).as_posix()
    lines = [
        BEGIN,
        "| concurrent agents | throughput | served p50 | served p95 | served p99 | listed p95 |",
        "|---|---|---|---|---|---|",
    ]
    for run in sorted(recorded, key=lambda r: int(r.get("users_requested") or 0)):
        lines.append(
            f"| {run['users_started']} | {run['throughput_rps']:.0f} req/s | "
            f"{_cell(run, 'served', 'p50_ms')} | {_cell(run, 'served', 'p95_ms')} | "
            f"{_cell(run, 'served', 'p99_ms')} | {_cell(run, 'listed', 'p95_ms')} |"
        )
    commit = str(record.get("commit", "?"))[:7]
    dirty = " (uncommitted changes)" if record.get("dirty") else ""
    flags = record.get("flags", "")
    lines.extend(
        [
            "",
            f"{record.get('run_seconds', RUN_SECONDS)}s per level, first "
            f"{record.get('warmup_seconds', '?')}s discarded, 0-50 ms think time per agent, "
            f"mock upstreams, no request throttled or failed (a run with either is refused); "
            f"[{when}, {where}]({path.relative_to(root).as_posix()}), "
            f"raw locust CSVs in [`{raw}/`]({raw}/); commit `{commit}`{dirty}; "
            f"switches `{flags}`.",
            END,
        ]
    )
    return "\n".join(lines)


_BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)


def current(text: str) -> str:
    found = _BLOCK.findall(text)
    if len(found) != 1:
        msg = f"expected exactly one {BEGIN} ... {END} block"
        raise LoadRecordError(msg)
    return str(found[0])


def replace(text: str, rendered: str) -> str:
    current(text)  # exactly one block, or refuse
    return _BLOCK.sub(lambda _: rendered, text)


def levels(values: Sequence[int] = LEVELS) -> tuple[int, ...]:
    """Validated concurrency levels: positive, ascending, distinct."""
    chosen = tuple(values)
    if not chosen or any(v <= 0 for v in chosen) or list(chosen) != sorted(set(chosen)):
        msg = f"levels must be positive, distinct and ascending, got {chosen!r}"
        raise LoadRecordError(msg)
    return chosen
