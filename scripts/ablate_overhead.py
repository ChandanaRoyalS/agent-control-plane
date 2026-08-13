#!/usr/bin/env python3
"""Itemise the gateway's fixed cost by removing one thing at a time.

    make up
    make overhead-ablate           # one pass, ~8 minutes
    make overhead-ablate-repeat    # three passes, ~25 minutes, tighter

Task 62. The ladder is `perf.overhead.ABLATION`; this walks it.

**Why an ablation and not a flamegraph.** ADR 0053 already made this argument
for the audit `fsync`: a controlled A/B shows *causation* where a profile shows
where time was spent. It holds harder here, because several of these costs are
not one function — screening is a loop over detectors, tracing is a span plus a
batched export on another thread, and `fsync` is a syscall that blocks. A
profiler attributes those to three different places; an ablation attributes them
to the switch an operator can actually turn.

**Why cumulative.** Each configuration keeps everything the ones above it
removed, so the steps sum to the total and the last row is a floor. An
interaction between two switches is billed to whichever is removed first —
stated in `ABLATION`'s docstring rather than buried here.

**Why the control is on every row, and why that turned out to be the point.**
The first version of this script printed the direct call once, at the bottom.
That was a reporting bug: the direct call is **the control** — the same request
to the same mock, doing identical work in every configuration — so its variation
across rungs is variation this harness introduced, and it is the only honest
scale to read the marginal column against.

Printed once, it hid that. Printed per rung, it says out loud how much of the
table is real. Four of the five rungs in the first run came in below it, two of
them negative, and the correct report of that is **"not resolved"** rather than
a small number a reader would try to explain.

**Each rung is a fresh gateway process and a fresh measurement process.** The
first is unavoidable — these are start-up settings. The second is deliberate: a
new token, a new connection pool and a cold cache each time, so no rung inherits
the previous rung's warm anything. It is also the source of most of the noise,
which is why `--repeat` exists: **these configurations cannot be interleaved,
only re-run.**
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf.overhead import Overhead, Rung, Step, classify_step, decode, ladder, resolution

ROOT = Path(__file__).resolve().parents[1]

POINT = 50
TAIL = 95

Payload = tuple[str, tuple[tuple[str, Overhead], ...]]


def emit(line: str = "") -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def restart(environment: dict[str, str]) -> bool:
    """Bring the gateway up under one configuration, waiting for it to be healthy.

    The overrides go into the *child's* environment rather than onto a command
    line, because that is where Compose reads interpolation from and because it
    keeps this process's own environment clean between rungs.
    """
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--wait", "gateway"],  # noqa: S607
        cwd=ROOT,
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr[-2000:] + "\n")
    return result.returncode == 0


def measure() -> Payload | None:
    """One measurement run, in its own process, returning its parsed payload."""
    result = subprocess.run(  # noqa: S603 — fixed argv, shell=False
        [sys.executable, str(ROOT / "scripts" / "measure_overhead.py"), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr[-2000:] + "\n")
        return None
    try:
        return decode(json.loads(result.stdout))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        sys.stderr.write(f"unreadable measurement payload: {exc}\n")
        return None


def pick(payload: Payload, label: str, point: int, *, control: bool) -> float | None:
    for name, result in payload[1]:
        if name == label:
            return (result.direct if control else result.gateway)[point]
    return None


def series(payloads: list[Payload], label: str, point: int, *, control: bool) -> list[float]:
    values = [pick(payload, label, point, control=control) for payload in payloads]
    return [value for value in values if value is not None]


def show(values: list[float]) -> str:
    """`17.8` for one run, `17.8 [17.2-18.4]` for several."""
    if not values:
        return "—"
    if len(values) == 1:
        return f"{values[0]:.1f}"
    return f"{statistics.mean(values):.1f} [{min(values):.1f}-{max(values):.1f}]"


MARKS = {Step.BELOW_FLOOR: "·", Step.IMPOSSIBLE: "?"}


def marginal(current: list[float], previous: list[float] | None, floor: float) -> str:
    """The step, or a mark saying what is wrong with believing it."""
    if previous is None or not current or not previous:
        return "—"
    step = statistics.mean(previous) - statistics.mean(current)
    verdict = classify_step(step, floor)
    if verdict is Step.RESOLVED:
        return f"{step:+.1f}"
    return MARKS[verdict]


def table(
    title: str,
    measured: list[tuple[Rung, list[Payload]]],
    label: str,
    point: int,
) -> tuple[float, int]:
    """One column of the ladder, judged against **its own** noise floor.

    Each table computes the floor from the control at *its own percentile*, and
    that is not a detail. The first version computed one floor from the control's
    p50 and applied it to the p95 column too — and the p95 column came back with
    two steps that were negative and above it, which is impossible as a cost and
    is the report saying the floor was wrong for that column.

    It was. **A tail is structurally noisier than a median**: a p95 is one of the
    slowest few samples, so it moves with whatever the machine happened to be
    doing, while a p50 sits where the distribution is densest. A floor measured
    at one percentile says nothing about the other.

    Returns `(floor, control count)` so the caller can report what it used.
    """
    controls = [
        value for _, payloads in measured for value in series(payloads, label, point, control=True)
    ]
    floor = resolution(controls)

    emit(f"  {title}")
    emit(f"  {'configuration':<24}{'gateway':>22}{'step':>10}{'control (direct)':>24}")
    emit(f"  {'-' * 24}{'-' * 21:>22}{'-' * 9:>10}{'-' * 23:>24}")
    previous: list[float] | None = None
    for rung, payloads in measured:
        gateway = series(payloads, label, point, control=False)
        control = series(payloads, label, point, control=True)
        emit(
            f"  {rung.label:<24}"
            f"{show(gateway):>22}"
            f"{marginal(gateway, previous, floor):>10}"
            f"{show(control):>24}"
        )
        previous = gateway
    emit(f"  {'':<24}{'':>22}{'':>10}{f'floor {floor:.1f} ms, n={len(controls)}':>24}")
    emit("")
    return floor, len(controls)


def passes() -> int:
    """How many times to walk the whole ladder. `--repeat N`, default 1."""
    arguments = sys.argv[1:]
    for index, argument in enumerate(arguments):
        if argument == "--repeat" and index + 1 < len(arguments):
            try:
                return max(1, int(arguments[index + 1]))
            except ValueError:
                return 1
    return 1


def report_resolution(median_floor: float, median_n: int, tail_floor: float, tail_n: int) -> None:
    emit("  RESOLUTION")
    if median_floor == float("inf"):
        emit("    Fewer than two control measurements, so NOTHING IS ATTRIBUTED and")
        emit("    every step prints as `·`. This should not happen with a full ladder.")
        return
    emit("    The control — the same request to the same mock, doing identical")
    emit("    work in every configuration — varied by:")
    emit("")
    emit(f"      {median_floor:>6.1f} ms at p50, across {median_n} runs")
    emit(f"      {tail_floor:>6.1f} ms at p95, across {tail_n} runs")
    emit("")
    emit("    EACH TABLE IS JUDGED AGAINST ITS OWN. A tail is structurally noisier")
    emit("    than a median — a p95 is one of the slowest few samples and moves")
    emit("    with whatever the machine was doing — so a floor measured at one")
    emit("    percentile says nothing about the other.")
    emit("")
    emit("    That variation is this harness's, not the gateway's, so a step at or")
    emit("    below it prints as `·` and is NOT attributed to what that row removed.")
    emit("")
    emit("    It is a LOWER BOUND. A step above it is not thereby resolved — the")
    emit("    gateway column carries this noise and its own on top.")
    emit("")
    emit("      ·   below the floor, so not attributed")
    emit(f"      ?   {Step.IMPOSSIBLE.value}")
    emit("          (removing work cannot make a system faster, so a negative step")
    emit("           this large means the floor understated that column's noise)")
    emit("")
    emit("    One pass already gives this, because the control is measured once per")
    emit("    configuration and each configuration is another container restart.")
    emit("    `--repeat` tightens the estimates; it is not what makes the floor exist.")


def main() -> int:
    repeats = passes()
    steps = ladder()
    emit("Itemising the gateway's fixed cost. Cumulative ablation, one request in flight.")
    emit(f"{len(steps)} configurations x {repeats} pass(es), each a fresh gateway and driver.")
    emit("")

    measured: list[tuple[Rung, list[Payload]]] = [(rung, []) for rung, _ in steps]
    for attempt in range(repeats):
        for position, (rung, environment) in enumerate(steps):
            emit(f"  pass {attempt + 1}: {rung.label} ...")
            if not restart(environment):
                msg = f"the gateway would not start under {rung.label}. Nothing further measured."
                raise SystemExit(msg)
            payload = measure()
            if payload is None:
                msg = f"the measurement failed under {rung.label}. Nothing further measured."
                raise SystemExit(msg)
            measured[position][1].append(payload)

    emit("")
    median_floor, median_n = table(
        "cache hit p50 — the fixed cost, touching no network", measured, "cache hit", POINT
    )
    tail_floor, tail_n = table("cache miss p95 — the tail", measured, "cache miss", TAIL)
    report_resolution(median_floor, median_n, tail_floor, tail_n)

    emit("")
    emit("  What each row removed:")
    for rung, _ in measured:
        if rung.removes:
            emit(f"    {rung.label:<24}{rung.removes}")
    emit("")
    emit("  The last row is a FLOOR, not zero. What remains in it: authentication,")
    emit("  policy evaluation, the audit write without its fsync, the pre-dispatch")
    emit("  check, the framework, and one extra network hop that exists because")
    emit("  something is in the middle at all. Read it against the control column.")
    emit("")
    emit("  Cumulative, so an interaction between two switches is charged to")
    emit("  whichever was removed first. See perf/overhead.py:ABLATION.")
    emit("")
    emit("  Restoring the defaults ...")
    restart({})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
