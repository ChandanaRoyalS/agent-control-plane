#!/usr/bin/env python3
"""Run the overhead harness and commit what it measured.

    make up
    make overhead-record                  # measure, write perf/results/, update README
    uv run python scripts/record_overhead.py --check   # README matches the newest file

Writes `perf/results/overhead-<date>-<commit>.json` and regenerates the README's
overhead rows from it (see `perf.record`). Commit both together: the file is the
evidence, the README is the quote.

Refuses to record from a dirty tree unless `--allow-dirty` is given, and says so
in the file when it is: a number measured on uncommitted code is a number
nobody can reproduce from the commit it names.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess  # fixed argv, no shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from perf.record import RESULTS, RecordError, block, current, latest, replace, rows  # noqa: E402

README = ROOT / "README.md"


def git(*args: str) -> str:
    completed = subprocess.run(  # noqa: S603 — fixed argv, shell=False
        ["git", *args],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def measure() -> dict[str, object]:
    """The harness's own JSON, from a subprocess so its stdout is the payload."""
    completed = subprocess.run(  # noqa: S603 — our own script, fixed argv
        [sys.executable, str(ROOT / "scripts" / "measure_overhead.py"), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        msg = "the overhead harness failed; nothing was recorded (is `make up` running?)"
        raise SystemExit(msg)
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        msg = "the overhead harness printed something other than a JSON object"
        raise SystemExit(msg)
    return payload


def check() -> int:
    try:
        path, record = latest()
        expected = block(path, record, root=ROOT)
        actual = current(README.read_text(encoding="utf-8"))
    except RecordError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    if actual != expected:
        print(
            f"FAILED: README overhead rows do not match {path.name}.\n"
            "  Run `uv run python scripts/record_overhead.py --render` and commit.",
            file=sys.stderr,
        )
        return 1
    print(f"README overhead rows match {path.name}.")
    return 0


def render() -> int:
    path, record = latest()
    README.write_text(
        replace(README.read_text(encoding="utf-8"), block(path, record, root=ROOT)),
        encoding="utf-8",
    )
    print(f"README overhead rows rendered from {path.name}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="README matches the newest record")
    mode.add_argument("--render", action="store_true", help="rewrite README from the newest record")
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

    measurement = measure()
    now = dt.datetime.now(dt.UTC)
    commit = git("rev-parse", "HEAD")
    record = {
        "recorded": now.isoformat(timespec="seconds"),
        "commit": commit,
        "dirty": dirty,
        "machine": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "measurement": measurement,
    }
    rows(record)  # refuse to write a record the README could not quote
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"overhead-{now:%Y-%m-%d}-{commit[:7]}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    render()
    print(f"Wrote {path.relative_to(ROOT)}. Commit it with README.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
