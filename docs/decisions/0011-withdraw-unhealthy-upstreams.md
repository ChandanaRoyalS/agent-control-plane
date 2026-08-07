# ADR 0011 — Withdraw unhealthy upstreams, and probe in the background

**Status:** accepted
**Date:** 2026-08-07

## Context

After task 14 the gateway knows when an upstream is failing. That knowledge
reaches the logs (task 15), a trace (16) and a dashboard (17) — which is to say
it reaches *operators*. The agent still asks for the full catalogue, still gets
a partial one, and is told nothing about why.

The circuit breaker also has a blind spot it cannot fix alone. It opens, waits
out its reset timeout, and then needs somebody to make a call before it will
half-open and discover whether the upstream came back. With no traffic there is
nobody. A gateway that goes quiet overnight wakes up with every circuit still
open, and the first agent of the morning pays a connect timeout to find out
otherwise.

## Decision

A `HealthMonitor` probes every upstream on a jittered interval, and the registry
omits an upstream found unhealthy from the merged catalogue entirely.

Probing means calling `tools/list` through the full stack. A readiness endpoint
on the admin listener reports what was found. An upstream that has never been
probed is **not** withdrawn.

## Alternatives considered

**Do nothing; the breaker already fast-fails.** True, and it misses both points.
The cost of a fast-failed call is microseconds rather than zero, but that is not
the argument — the argument is that a fast-failed call still produces a partial
catalogue with no explanation, and that a breaker with no traffic never
recovers.

**A dedicated health method on the upstream.** MCP has none, and inventing one
would be worse than using `tools/list`: a synthetic ping can succeed while the
operation the gateway actually needs is broken. The probe is the real request,
so a green probe means something.

**Probe outside the breaker, so probes do not count as failures.** Tempting, and
backwards. Probes counting is the mechanism: they are what drives an open
breaker to half-open without an agent having to volunteer, so the scheduled task
pays the timeout instead of whichever request happened to be next.

**Withdraw on `UNKNOWN` as well.** Symmetrical and dangerous. A monitor that
failed to start, or has not finished its first round, would produce a gateway
that serves no tools at all — a monitoring bug escalated into a total outage.
Unknown means ask. Note this is the *opposite* of the deny-by-default posture
the policy engine will take in Phase 3, and deliberately so: that is
authorisation, this is availability, and they fail in opposite directions for
good reasons.

**Merge withdrawals into `Catalogue.failures`.** One field instead of two, and
it loses a distinction that matters operationally. A failure is a surprise worth
a warning on the request that hit it. A withdrawal is a known condition, already
logged once when it began. Merging them means an upstream that has been down for
an hour logs a warning on every request for that hour, which is how the useful
signal gets buried.

**Log every probe result.** A probe every fifteen seconds forever is a log line
every fifteen seconds forever. Only transitions are logged — the same rule that
keeps the metrics scrape out of the request log.

**Readiness that fails whenever any upstream is unhealthy.** Would take the
whole fleet out of rotation for one degraded dependency, which is precisely the
partial-failure policy inverted. `/readyz` fails only when upstreams are
configured and *none* can serve, mirroring `Catalogue.is_total_failure`.

**Readiness that never fails.** Also defensible — it would keep the fleet
serving useful error messages rather than connection refusals. Rejected because
at total failure every `tools/list` raises anyway, so reporting ready is a lie a
load balancer believes. The accepted consequence is stated below.

**Starting the probe loop inside `gateway_from_configs`.** The obvious place,
and it puts a long-lived task's cancel scope in a different task from the one
that exits the async generator — the classic way to get a cancellation firing
somewhere unexpected. The loop is started by the CLI, where a task group already
legitimately lives, and the monitor is attached to `app.state` so the existing
signature and every test using it are unchanged.

## Consequences

An agent connected during an outage sees a smaller tool list rather than a full
one with failures behind it. A tool it never sees is a tool it will not call and
will plan around — which is a better outcome than calling it and handling an
error, and is the first time the breaker's knowledge has reached the caller.

Recovery no longer requires traffic. The scheduled probe is the breaker's trial
call, so an idle gateway heals itself.

The probe interval is jittered, for the same reason retry backoff is: every
replica probing on the same tick is a synchronised burst against every upstream,
from the component whose whole purpose is to prevent exactly that.

Health lives in `acp.health`, not `acp.gateway.health`. Putting it under
`acp.gateway` made the admin app import the inbound server and therefore the MCP
SDK — a dependency a metrics-and-readiness listener has no reason to carry, and
one that would have made these tests impossible to run without it.

**Accepted risk:** every replica shares the same upstreams, so a total upstream
outage fails readiness on all of them simultaneously. The alternative is a fleet
reporting ready while erroring every request, which is worse for whoever is
reading a dashboard at the time. If this becomes a problem in practice the fix
is a minimum-ready floor rather than reverting the signal.

**Also accepted:** withdrawal is only as fresh as the last probe, so there is a
window of up to one interval in which the catalogue still advertises an upstream
that has just died. The breaker covers that window — the call fails fast rather
than slowly — which is why the two mechanisms are complementary rather than
redundant.
