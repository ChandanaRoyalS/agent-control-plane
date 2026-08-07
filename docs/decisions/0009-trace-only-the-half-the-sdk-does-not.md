# ADR 0009 — Trace only the half the SDK does not

**Status:** accepted
**Date:** 2026-08-06
**Extends:** [ADR 0005](0005-hybrid-protocol-layer.md), [ADR 0007](0007-structured-logging-on-the-standard-library.md)

## Context

Task 16 called for OpenTelemetry tracing: one tool call should produce one
connected trace spanning the gateway and the upstream it forwards to.

Reading the installed SDK before writing anything changed the shape of the work
substantially. `mcp/server/lowlevel/server.py:439` installs
`OpenTelemetryMiddleware` into every server's middleware list *by default*. That
middleware already opens a `SERVER` span per inbound request, names it
`{method} {target}`, sets `mcp.method.name`, `mcp.protocol.version`,
`jsonrpc.request.id`, `gen_ai.operation.name = "execute_tool"` and
`gen_ai.tool.name`, handles the error cases, and — importantly — extracts the
parent context from `params._meta`.

OpenTelemetry was also already installed, as a transitive dependency of `mcp`.

The gap is precisely the half ADR 0005 hand-rolled. The SDK's client dispatcher
creates `CLIENT` spans and injects trace context, but the gateway does not use
the SDK's client. So without new code, a trace would show the agent's request
arriving at the gateway and stopping — at exactly the boundary a trace exists to
cross.

Two details from the specifications shape the rest. MCP's SEP-414 makes
`traceparent`, `tracestate` and `baggage` a documented **exception** to the
`_meta` namespacing rule, carried unprefixed, explicitly so that traces do not
break between implementations that disagree about a prefix. And the GenAI
conventions mark `gen_ai.tool.call.arguments` and `.result` as opt-in.

## Decision

Instrument the outbound half only. Every upstream request gets a `CLIENT` span
with attributes from `acp.observability.semconv`, and the W3C trace context is
injected into that request's `params._meta`, unprefixed.

Do not create an inbound span. The SDK's is already correct.

Trace and span IDs are merged onto every log record by the existing
`ContextFilter`, closing the loop ADR 0007 opened: a log line pivots to its
trace, and a slow span pivots to the log lines explaining it.

Tool arguments and results are never recorded on a span.

Configuration is by OpenTelemetry's standard environment variables, and tracing
is off unless `OTEL_TRACES_EXPORTER` names an exporter.

## Alternatives considered

**Create our own inbound span too.** Rejected: two spans per request describing
the same operation, with the second adding nothing the first lacks. If gateway
attributes are needed on the inbound span later, the SDK exposes
`server.middleware` as a mutable list, so one can be appended — the seam exists
without needing a competing span today.

**Use the SDK's `inject_trace_context` helper for our outbound requests.** One
import, already written. Rejected because it lives in `mcp.shared._otel`, a
private module, and because ADR 0005 keeps the outbound half free of the SDK.
OpenTelemetry's public `propagate.inject` is the same single call against a
stable API, and the SDK helper is a thin wrapper over exactly that.

**Auto-instrument httpx.** Would produce spans for free. Rejected: they would be
generic HTTP client spans, with no `mcp.method.name`, no tool name and no
upstream identity — none of the attributes anyone would actually slice by. The
whole value here is that a span says "this is a tool call to `mock-a` that timed
out", not "this is a POST that took 30 seconds".

**Record tool arguments and results.** They would make traces far more useful
for debugging, which is exactly why the conventions mark them opt-in rather than
forbidden. Rejected as a default: arguments routinely carry queries,
identifiers, personal data and occasionally credentials, and a span goes to a
system with a different audience and a different retention policy than the
gateway's own logs. ADR 0007 put redaction in the log pipeline; putting the
unredacted values in a span would walk straight around it. Revisit only behind
an explicit setting and only running through the same redaction.

**Record exceptions on the span.** `record_exception=True` is the OpenTelemetry
default and captures the message and stack trace. Turned off, with `error.type`
and a fixed low-cardinality description set instead — exception messages here
quote URLs, arguments and upstream responses. The SDK's own middleware makes the
same choice, in its words because "pydantic messages carry client input".

**`ACP_`-prefixed settings for the endpoint and exporter.** Consistent with the
rest of our configuration, and rejected anyway. `OTEL_EXPORTER_OTLP_ENDPOINT`
and friends are a standard that every operator, sidecar and Kubernetes operator
already knows and already sets. Inventing a parallel vocabulary for a solved
problem is how a service becomes annoying to run.

**A simple span processor rather than a batch one.** Simpler, and it puts a
network call on the request path — so a slow collector becomes slow tool calls.
That is the precise failure the circuit breaker exists to prevent, reintroduced
by the thing meant to observe it.

## Consequences

A single trace now shows the agent's call, the gateway's fan-out to every
upstream, which one was slow, and which one refused because its circuit was
open. An upstream that is itself instrumented continues the same trace rather
than starting a new one.

The tracing module guards its OpenTelemetry import and degrades to a no-op
throughout. In a correctly installed gateway that branch never runs, and it is
there because telemetry failing must never be able to take the gateway down —
and because it makes the untraced path, which is what most deployments run,
directly testable.

`structlog` was removed from the dependencies. ADR 0007 chose the standard
library and nothing has imported structlog since; a declared dependency nobody
imports is a thing future readers assume is load-bearing.

The cost is a dependency on SDK behaviour we do not control: if a future release
stops installing `OpenTelemetryMiddleware` by default, inbound spans disappear
silently and the only symptom is orphaned client spans. That is worth a test
once there is a clean way to assert it — the same reasoning that produced
`test_spec_conformance.py`, and the same failure mode, one layer up.
