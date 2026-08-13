"""Locust wiring for the gateway load test — task 60.

    make load          # 30s, 20 users, against the composed stack
    make load-long     # 5 minutes, 100 users
    uv run locust -f perf/locustfile.py --host http://127.0.0.1:8080   # web UI

Everything decidable lives in `perf/scenarios.py`, which has no Locust import
and is unit-tested. This file is the part that cannot be: gevent, the user
model, and the reporting hook.

**Three things this does that a default Locust file does not**, each because
the default would produce a confidently wrong number:

1. **It refuses to run against a chaos-injecting mock fleet.** `CHAOS_MODE` is
   a process-wide environment variable on the mocks, so a run left over from a
   resilience experiment silently measures the injected latency instead of the
   gateway. The check costs one request and turns a plausible bad number into a
   loud refusal.
2. **It mints one token per simulated user and reuses it.** Fetching a token
   per request would make this a Keycloak benchmark with a gateway attached —
   and Keycloak is the slowest thing in the compose stack by an order of
   magnitude.
3. **It reports latency per outcome, not in aggregate.** See
   `perf.scenarios.Outcome`: a p95 across served, refused and held calls is a
   statement about the task mix rather than about the gateway.
"""

from __future__ import annotations

import itertools
import os
import sys
import time
from collections import defaultdict
from typing import Any

import gevent
from gevent.lock import Semaphore
from locust import HttpUser, between, events, task

from perf.scenarios import (
    MIX,
    UNIQUE_MARKER,
    WARMUP_SECONDS,
    Call,
    Outcome,
    after_warmup,
    classify,
    percentiles,
    principal_for,
)

MINT_FAILURE_HINT = (
    "could not mint a token. Is the stack up (`make up`) and Keycloak "
    "reachable on :8081? Run `make token` to see the real error."
)

# (seconds since run start, latency in ms), per outcome, across every user in
# this process. Locust's own stats are keyed by request name; these are keyed
# by what the gateway *did*, which is the axis this project cares about.
_SAMPLES: dict[str, list[tuple[float, float]]] = defaultdict(list)

_STARTED_AT = 0.0
_SPAWNED = 0
_FAILED_TO_START = 0

TOKEN_RETRIES = 5
TOKEN_BACKOFF = 0.4
"""Keycloak's realm sets `bruteForceProtected: true`, and twenty greenlets
logging in at once looks exactly like a password-guessing attack — because it
is one, structurally. The lockout answers `invalid_grant: Invalid user
credentials`, which is deliberately indistinguishable from a wrong password
and is what made the first run of this harness look like a credentials bug.

The real fix is `_TokenPool` below, which reduces twenty logins to two. This
retry is the belt: a shared stack that has just served another run may still be
inside a lockout window when this one starts."""


class _TokenPool:
    """One token per principal, per process, minted once and shared.

    The first version of this harness minted a token **per simulated user** —
    twenty simultaneous logins for the same account against a
    brute-force-protected realm. Keycloak locked it, and half the fleet died
    before sending a single request.

    ADR 0052 already argued that per-*request* minting would make this a
    Keycloak benchmark with a gateway attached. Per-*user* minting was the same
    mistake moved to startup, where it was harder to see: the run still printed
    a full report, from the users that survived.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}
        self._lock = Semaphore()

    def get(self, user: str) -> str:
        """This principal's token, minting it at most once per process."""
        with self._lock:
            held = self._tokens.get(user)
            if held is not None:
                return held
            token = self._mint(user)
            self._tokens[user] = token
            return token

    def _mint(self, user: str) -> str:
        from scripts.keycloak_token import access_token  # noqa: PLC0415 — optional at import

        last: Exception | None = None
        for attempt in range(TOKEN_RETRIES):
            try:
                return access_token(user)
            except Exception as exc:  # retried below, then re-raised with context
                last = exc
                gevent.sleep(TOKEN_BACKOFF * (attempt + 1))
        emit(f"{MINT_FAILURE_HINT}\n  {type(last).__name__}: {last}", error=True)
        raise RuntimeError(str(last))


_TOKENS = _TokenPool()
_NEXT_USER = itertools.count()


def emit(line: str = "", *, error: bool = False) -> None:
    """The harness's only way of speaking.

    One seam rather than eighteen calls, so a `--json` report is a change to
    one function. It writes to the stream directly rather than calling `print`,
    which keeps the file lint-clean under `T20` without a suppression — and a
    suppression whose necessity depends on the linter's version is a line that
    fails on somebody else's machine.
    """
    stream = sys.stderr if error else sys.stdout
    stream.write(line + "\n")


def _weighted(mix: tuple[Call, ...]) -> list[Call]:
    """Locust's `@task(weight)` is per method; the mix is data, so expand it."""
    expanded: list[Call] = []
    for call in mix:
        expanded.extend([call] * call.weight)
    return expanded


_WEIGHTED = _weighted(MIX)


class GatewayUser(HttpUser):
    """One simulated agent, holding one principal's token for its lifetime."""

    wait_time = between(0.0, 0.05)
    """Near-zero, deliberately. This is a saturation test of a local stack, not
    a simulation of human think-time — the question is what the gateway does
    when asked as fast as it can be asked. `perf/README.md` says so, because a
    throughput number without its wait time is not reproducible."""

    def on_start(self) -> None:
        """Take this user's principal and its shared token.

        The principal comes from an explicit round-robin counter, not from
        anything derived from the object: `principal_for` explains why the
        first version never alternated.
        """
        global _SPAWNED, _FAILED_TO_START  # noqa: PLW0603 — process-wide run counters
        self.user_name = principal_for(next(_NEXT_USER))
        try:
            self.token: str = _TOKENS.get(self.user_name)
        except Exception:
            _FAILED_TO_START += 1
            raise
        _SPAWNED += 1
        self.counter = 0

    @task
    def call(self) -> None:
        """One request from the weighted mix, classified by what came back."""
        self.counter += 1
        chosen = _WEIGHTED[self.counter % len(_WEIGHTED)]

        body = chosen.body(request_id=self.counter)
        if chosen.arguments and UNIQUE_MARKER in chosen.arguments.values():
            # Make the cache miss on purpose, per request. `environment.runner`
            # is included so two workers cannot collide on the same query and
            # accidentally warm each other's entries.
            arguments = body["params"]["arguments"]
            for key, value in list(arguments.items()):
                if value == UNIQUE_MARKER:
                    arguments[key] = f"q-{os.getpid()}-{self.counter}"

        with self.client.post(
            "/mcp",
            json=body,
            headers=chosen.headers(self.token),
            name=chosen.name,
            catch_response=True,
        ) as response:
            outcome = classify(response.status_code, response.text)
            _SAMPLES[str(outcome)].append(
                (time.monotonic() - _STARTED_AT, response.elapsed.total_seconds() * 1000)
            )
            if outcome is Outcome.FAILED:
                response.failure(f"unclassifiable: HTTP {response.status_code}")
            else:
                # Everything else is the gateway working, including refusals.
                # Locust's error rate should count defects, not defences.
                response.success()


@events.test_start.add_listener
def refuse_to_measure_a_chaos_run(environment: Any, **_: Any) -> None:
    """A run against a chaos-injecting mock fleet measures the chaos.

    `CHAOS_MODE` is process-wide on the mocks and survives whatever experiment
    set it. The failure it causes is the project's most repeated shape — valid
    input, no error, silently different behaviour — and the symptom would be a
    p99 somebody writes into a README.

    Checked from the *host's* environment, which is where `docker compose`
    would have read it from. It cannot see a value baked into a running
    container, so this is a cheap guard rather than a proof, and the README
    says to `make down && make up` if a number looks wrong.
    """
    global _STARTED_AT  # noqa: PLW0603 — the run's own clock origin
    _STARTED_AT = time.monotonic()

    mode = os.environ.get("CHAOS_MODE")
    if mode and mode.lower() not in {"none", ""}:
        message = (
            f"CHAOS_MODE={mode!r} is set. A load test against a mock fleet that "
            f"injects latency or errors measures the injection, not the gateway. "
            f"Unset it and restart the stack before measuring."
        )
        emit(f"\nREFUSING TO RUN: {message}\n", error=True)
        environment.runner.quit()
        raise SystemExit(1)


@events.test_stop.add_listener
def report_by_outcome(environment: Any, **_: Any) -> None:
    """Print the table this harness exists to produce.

    Locust's own summary is by request name and in aggregate. This one is by
    *what the gateway did*, which is the only grouping under which the numbers
    mean one thing each.
    """
    stats = environment.stats.total
    total = sum(len(v) for v in _SAMPLES.values())
    requested = getattr(environment.parsed_options, "num_users", None)

    emit("\n" + "=" * 72)
    emit("Agent Control Plane — load test, by outcome")
    emit("=" * 72)

    # How many users ACTUALLY ran. The first version of this harness lost half
    # its fleet to a Keycloak lockout at startup and printed a confident table
    # anyway — numbers for ten users under a heading that implied twenty.
    fleet = f"  users      {_SPAWNED} started"
    if requested:
        fleet += f" of {requested} requested"
    if _FAILED_TO_START:
        fleet += f", {_FAILED_TO_START} FAILED TO START"
    emit(fleet)
    emit(f"  requests   {total}")
    emit(f"  throughput {stats.total_rps:.1f} req/s")
    emit("  wait time  0-50 ms between requests, per user")
    emit(f"  warm-up    first {WARMUP_SECONDS:.0f}s discarded from the percentiles")
    emit()
    emit(f"  {'outcome':<12} {'count':>7} {'share':>7} {'p50':>9} {'p95':>9} {'p99':>9}")
    emit(f"  {'-' * 12} {'-' * 7} {'-' * 7} {'-' * 9} {'-' * 9} {'-' * 9}")

    discarded = 0
    for name in (o.value for o in Outcome):
        samples = _SAMPLES.get(name, [])
        if not samples:
            continue
        warm = after_warmup(samples)
        discarded += len(samples) - len(warm)
        marks = percentiles(warm)
        share = 100 * len(samples) / total if total else 0.0
        emit(
            f"  {name:<12} {len(samples):>7} {share:>6.1f}% "
            f"{marks[50]:>8.1f}ms {marks[95]:>8.1f}ms {marks[99]:>8.1f}ms"
        )

    emit()
    if discarded:
        emit(f"  {discarded} sample(s) discarded as warm-up.")
    if _FAILED_TO_START:
        emit("  ⚠ SOME USERS NEVER STARTED. The table above describes the fleet that")
        emit("    did — a smaller one than was asked for, at lower concurrency.")
    if _SAMPLES.get(Outcome.FAILED.value):
        emit("  ⚠ FAILED is non-zero. Those are defects, not defences — read the")
        emit("    gateway's logs before believing any number above.")
    if _SAMPLES.get(Outcome.UPSTREAM.value):
        emit("  ⚠ UPSTREAM is non-zero. A mock could not keep up, so this run measured")
        emit("    the mock fleet as much as the gateway. Lower the user count.")
    if _SAMPLES.get(Outcome.THROTTLED.value):
        emit("  ⚠ THROTTLED is non-zero. This run measured the rate limiter, so the")
        emit("    latencies above describe a queue as much as a gateway.")
    if _SAMPLES.get(Outcome.UNRECORDED.value):
        emit("  ⚠ UNRECORDED is non-zero. The audit sink could not keep up and those")
        emit("    calls did not happen (fail-closed). fsync-per-entry is the suspect.")
    emit(
        "  These numbers describe THIS machine, THIS mock fleet and THIS mix.\n"
        "  They are not a benchmark of anything. See perf/README.md."
    )
    emit("=" * 72)
