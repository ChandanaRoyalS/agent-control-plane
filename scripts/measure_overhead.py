#!/usr/bin/env python3
"""Measure what the gateway adds, against calling the upstream directly.

    make up
    make overhead

Task 62. The decisions are in `perf/overhead.py`; this is the driver.

**Sequential, one request in flight.** Overhead is the work the gateway does
that the upstream would not have done, and it is only visible when nothing is
queueing. Task 60's harness measures the opposite question — what happens when
it is busy — and its p50 of ~300 ms is a statement about a queue. Both are
true; only this one is the gateway's cost.

**Alternating blocks, three rounds.** Task 61 found that a laptop warms
measurably over five minutes, so a direct-then-gateway ordering would charge
the whole drift to whichever ran second. Alternating spreads it evenly, and
every number printed carries its range.

**It reads the gateway's configuration before it reports a number.** Most of
the expensive work is optional and most of the switches default to off, so
"3 ms" without the switch settings is not a measurement of anything. The
environment comes out of the running container rather than the compose file,
because the two disagree the moment anybody sets a variable on the command
line — which `make load-nofsync` does.
"""

from __future__ import annotations

import asyncio
import json
import subprocess  # one fixed argv, no shell — see `gateway_environment`
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf.overhead import (
    ALWAYS_ON,
    BACKGROUND,
    CONTAINER,
    GATEWAY,
    MEASURED,
    Measurement,
    Overhead,
    applicable,
    compare,
    direct_request,
    encode,
    features,
    flags,
    parse_env,
    uniquify,
)
from perf.scenarios import Outcome, classify

ROUNDS = 3
CALLS = 60
"""Per row, per path, per round. 60 x 3 = 180 samples each side, which is
enough for a stable p95 and short enough that the machine does not drift far
inside one round."""

WARMUP = 10
"""Discarded. The first calls pay for a cold connection pool, a cold JWKS
cache, an uncached credential exchange and a cold result cache — real costs,
and not the steady-state figure this reports."""

POINTS = (50, 95, 99)


def emit(line: str = "") -> None:
    sys.stdout.write(line + "\n")


def gateway_environment() -> dict[str, str]:
    """The running gateway's actual environment, via `docker inspect`.

    A fixed argument list and no shell, so there is nothing here for a
    container name to inject into. Returns empty rather than raising when
    Docker is absent or the container is not up: the caller turns that into a
    refusal with a readable reason, which is more use than a traceback.
    """
    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, shell=False
            ["docker", "inspect", CONTAINER, "--format", "{{json .Config.Env}}"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if completed.returncode != 0:
        return {}
    try:
        entries = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}
    if not isinstance(entries, list):
        return {}
    return parse_env([entry for entry in entries if isinstance(entry, str)])


def report_configuration(env: dict[str, str]) -> None:
    """Print what this gateway was doing, before printing what it cost."""
    emit("  This gateway's configuration, read from the running container:")
    emit("")
    for feature, on in features(env):
        mark = "on " if on else "OFF"
        emit(f"    [{mark}] {feature.name:<22} {feature.adds}")
    emit("")
    emit("  Not switchable, and in every number below:")
    for item in ALWAYS_ON:
        emit(f"    [on ] {item}")
    emit("")
    emit("  Not on the request path, and competing with it anyway:")
    for feature in BACKGROUND:
        mark = "on " if feature.enabled(env) else "OFF"
        emit(f"    [{mark}] {feature.name:<22} {feature.adds}")
    emit("")
    emit("  An OFF row is work this gateway did not do, so the figures below")
    emit("  understate a deployment that switches it on. That is the whole")
    emit("  reason this table is printed above the numbers rather than omitted.")
    emit("")


async def token() -> str:
    from scripts.keycloak_token import access_token  # noqa: PLC0415

    return await asyncio.to_thread(access_token, "alice")


async def timed(
    client: httpx.AsyncClient,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
) -> tuple[float, Outcome]:
    """One call, in milliseconds, with what came back."""
    started = time.perf_counter()
    response = await client.post(url, json=body, headers=headers, timeout=30.0)
    elapsed = (time.perf_counter() - started) * 1000
    return elapsed, classify(response.status_code, response.text)


async def block(
    client: httpx.AsyncClient,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    unique: bool,
    start: int,
) -> list[float]:
    """One block of sequential calls, warm-up discarded.

    `unique` is the measurement's, not the driver's opinion: forcing every
    request to miss the cache is right for the cache-miss row and destroys the
    cache-hit row, so the decision lives with the row.
    """
    samples: list[float] = []
    for index in range(CALLS):
        payload = uniquify(body, start + index) if unique else body
        elapsed, outcome = await timed(client, url, payload, headers)
        if outcome is Outcome.FAILED:
            msg = f"unclassifiable response from {url} — is the stack up and healthy?"
            raise SystemExit(msg)
        if outcome is Outcome.REFUSED:
            msg = (
                f"the gateway refused {url} — the composed policy should allow "
                f"alice to call search. Nothing was measured."
            )
            raise SystemExit(msg)
        if index >= WARMUP:
            samples.append(elapsed)
    return samples


async def measure(
    client: httpx.AsyncClient, bearer: str, measurement: Measurement
) -> tuple[Measurement, Overhead]:
    """Both distributions for one row, alternating round by round."""
    call = measurement.call
    url, direct_body, direct_headers = direct_request(call)
    gateway_body = call.body()
    gateway_headers = call.headers(bearer)

    gateway_samples: list[float] = []
    direct_samples: list[float] = []

    for round_index in range(ROUNDS):
        offset = round_index * CALLS * 2
        # Alternating, so the machine's drift over the run is charged evenly to
        # both paths rather than to whichever went second.
        gateway_samples += await block(
            client,
            GATEWAY,
            gateway_body,
            gateway_headers,
            unique=measurement.unique,
            start=offset,
        )
        direct_samples += await block(
            client,
            url,
            direct_body,
            direct_headers,
            unique=measurement.unique,
            start=offset + CALLS,
        )

    return measurement, compare(measurement.tool, gateway_samples, direct_samples)


def report_skips(
    skipped: Sequence[tuple[Measurement, str]], *, brief: bool, emit_json: bool
) -> None:
    """Say what was not measured, in whichever voice the caller asked for.

    Never silent, even in `--json`: a row missing from the payload without a
    reason is how a skipped measurement becomes an absent one.
    """
    for measurement, reason in skipped:
        if emit_json:
            sys.stderr.write(f"SKIPPED: {measurement.label} — {reason}.\n")
        elif brief:
            emit(f"    SKIPPED: {measurement.label} — {reason}.")
        else:
            emit(f"  SKIPPED: {measurement.label} — {reason}.")
            emit(f"  {'':<11}Running it anyway would print a plausible row measuring")
            emit(f"  {'':<11}something else, so it is not run.")
            emit("")


def report_brief(measurement: Measurement, result: Overhead) -> None:
    """One line per row, for a run that prints several configurations.

    The full report is right once and unreadable four times in a row — and an
    A/B whose output nobody reads to the end is an A/B that produces a
    conclusion drawn from the first block.
    """
    emit(
        f"    {measurement.label:<12}"
        f"direct {result.direct[50]:>6.1f} / gateway {result.gateway[50]:>6.1f}"
        f" / added {result.added[50]:>+7.1f}ms p50"
        f"   ({result.added[95]:+.1f}ms p95)"
    )


def report_row(measurement: Measurement, result: Overhead) -> None:
    emit(f"  {measurement.label} — {measurement.tool}")
    emit(f"  {'':<4}{'':>10}" + "".join(f"{f'p{p}':>11}" for p in POINTS))
    emit(f"  {'':<4}{'direct':>10}" + "".join(f"{result.direct[p]:>9.1f}ms" for p in POINTS))
    emit(f"  {'':<4}{'gateway':>10}" + "".join(f"{result.gateway[p]:>9.1f}ms" for p in POINTS))
    emit(
        f"  {'':<4}{'ADDED':>10}"
        + "".join(f"{result.added[p]:>+9.1f}ms" for p in POINTS)
        + f"   ({result.multiple:.2f}x at p50)"
    )
    emit(f"  {'':<4}{result.samples} samples each side")
    emit(f"  {'':<4}{measurement.why}")
    emit("")


async def main() -> int:
    brief = "--brief" in sys.argv[1:]
    emit_json = "--json" in sys.argv[1:]
    quiet = brief or emit_json

    if not quiet:
        emit("Measuring gateway overhead. Sequential, one request in flight.")
        emit(f"{ROUNDS} rounds x {CALLS} calls per path per row ({WARMUP} discarded as warm-up).")
        emit("")

    env = gateway_environment()
    if not env:
        msg = (
            f"could not read the environment of the `{CONTAINER}` container. "
            f"Is the stack up (`make up`)? Refusing to publish an overhead "
            f"number without the configuration that produced it."
        )
        raise SystemExit(msg)

    if brief:
        emit(f"  {flags(env)}")
    elif not emit_json:
        report_configuration(env)

    runnable, skipped = applicable(env, MEASURED)
    report_skips(skipped, brief=brief, emit_json=emit_json)
    if not runnable:
        msg = "no measurement is applicable to this gateway's configuration."
        raise SystemExit(msg)

    bearer = await token()
    results: list[tuple[Measurement, Overhead]] = []
    async with httpx.AsyncClient() as client:
        for measurement in runnable:
            results.append(await measure(client, bearer, measurement))

    if emit_json:
        # stdout is the channel and the only thing on it, so the caller can
        # parse it without stripping a banner it did not ask for.
        emit(json.dumps(encode(flags(env), [(m.label, r) for m, r in results])))
        return 0

    if brief:
        for measurement, result in results:
            report_brief(measurement, result)
        return 0

    for measurement, result in results:
        report_row(measurement, result)

    emit("  The difference is the work in the [on] rows above, plus one extra")
    emit("  network hop — which is not the gateway's job but is unavoidable when")
    emit("  something sits in the middle, and is counted here rather than netted")
    emit("  out. The direct path is also unauthenticated, because the mock has no")
    emit("  auth to offer; that difference is counted as overhead on purpose.")
    emit("")
    emit("  ONE MACHINE, MOCK UPSTREAMS THAT ANSWER IN MICROSECONDS. Against a")
    emit("  real upstream this cost sits under the network. See perf/README.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
