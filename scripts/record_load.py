#!/usr/bin/env python3
"""Run the load test at each concurrency level and commit what it measured.

    make up
    make load-record                                  # measure, write perf/results/, update README
    uv run python scripts/record_load.py --check      # README matches the newest summary

For each level in `perf.load.LEVELS` (20 and 50 agents), runs the locust
harness headless for `RUN_SECONDS`, keeps locust's raw CSVs under
`perf/results/load-<date>-<commit>/u<N>_*.csv`, and writes one summary
`perf/results/load-<date>-<commit>.json`. Regenerates the README's load rows
from it. Commit the directory, the summary and README together: the CSVs are
the evidence, the summary is the reading, the README is the quote.

Refuses a dirty tree unless `--allow-dirty`, as `record_overhead.py` does, and
refuses to write a run that lost users at startup or served nothing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess  # fixed argv, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from perf.load import (  # noqa: E402
    LEVELS,
    RESULTS,
    RUN_SECONDS,
    LoadRecordError,
    block,
    current,
    latest,
    replace,
    runs,
)
from perf.overhead import flags, parse_env  # noqa: E402
from perf.scenarios import WARMUP_SECONDS  # noqa: E402

README = ROOT / "README.md"
CONTAINER = "acp-gateway"
SUMMARY_ENV = "ACP_LOAD_SUMMARY"


def git(*args: str) -> str:
    completed = subprocess.run(  # noqa: S603 — fixed argv, shell=False
        ["git", *args],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def gateway_flags() -> str:
    """The running gateway's switch settings, as the overhead record states them."""
    completed = subprocess.run(  # noqa: S603 — fixed argv, shell=False
        ["docker", "inspect", CONTAINER, "--format", "{{json .Config.Env}}"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        msg = f"cannot read the `{CONTAINER}` container's environment; is `make up` running?"
        raise SystemExit(msg)
    return flags(parse_env(json.loads(completed.stdout)))


def run_level(users: int, raw: Path) -> dict[str, object]:
    """One locust run; its summary, with the raw CSVs left in ``raw``."""
    with tempfile.TemporaryDirectory() as scratch:
        summary = Path(scratch) / "summary.json"
        completed = subprocess.run(  # noqa: S603 — fixed argv, shell=False
            [
                sys.executable,
                "-m",
                "locust",
                "-f",
                str(ROOT / "perf" / "locustfile.py"),
                "--host",
                "http://127.0.0.1:8080",
                "--headless",
                "--users",
                str(users),
                "--spawn-rate",
                "10",
                "--run-time",
                f"{RUN_SECONDS}s",
                "--csv",
                str(raw / f"u{users}"),
                "--only-summary",
            ],
            cwd=ROOT,
            env={**os.environ, SUMMARY_ENV: str(summary)},
            capture_output=True,
            text=True,
            check=False,
        )
        sys.stdout.write(completed.stdout)
        if not summary.exists():
            sys.stderr.write(completed.stderr[-2000:])
            msg = f"the {users}-user run wrote no summary; nothing was recorded"
            raise SystemExit(msg)
        loaded: dict[str, object] = json.loads(summary.read_text(encoding="utf-8"))
        return loaded


def check() -> int:
    try:
        expected = block(latest(), root=ROOT)
        actual = current(README.read_text(encoding="utf-8"))
    except LoadRecordError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    if actual != expected:
        print(
            "FAILED: README load rows do not match the newest summary.\n"
            "  Run `uv run python scripts/record_load.py --render` and commit.",
            file=sys.stderr,
        )
        return 1
    print("README load rows match the newest summary.")
    return 0


def render() -> int:
    README.write_text(
        replace(README.read_text(encoding="utf-8"), block(latest(), root=ROOT)),
        encoding="utf-8",
    )
    print("README load rows rendered.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="README matches the newest summary")
    mode.add_argument("--render", action="store_true", help="rewrite README from the newest one")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check()
    if args.render:
        return render()

    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    if dirty and not args.allow_dirty:
        msg = (
            "the working tree has uncommitted changes; a result recorded now would name "
            "a commit that is not what ran. Commit or stash, or pass --allow-dirty."
        )
        raise SystemExit(msg)

    now = dt.datetime.now(dt.UTC)
    commit = git("rev-parse", "HEAD")
    stem = f"load-{now:%Y-%m-%d}-{commit[:7]}"
    raw = RESULTS / stem
    raw.mkdir(parents=True, exist_ok=True)
    switches = gateway_flags()

    measured = []
    for users in LEVELS:
        print(f"=== {users} concurrent agents, {RUN_SECONDS}s. Do not use the machine. ===")
        measured.append(run_level(users, raw))

    record = {
        "recorded": now.isoformat(timespec="seconds"),
        "commit": commit,
        "dirty": dirty,
        "flags": switches,
        "run_seconds": RUN_SECONDS,
        "warmup_seconds": WARMUP_SECONDS,
        "machine": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "runs": measured,
    }
    runs(record)  # refuse to write what the README could not honestly quote
    path = RESULTS / f"{stem}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    render()
    print(
        f"Wrote {path.relative_to(ROOT)} and {raw.relative_to(ROOT)}/. Commit them with README.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
