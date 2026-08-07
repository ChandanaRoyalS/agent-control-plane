# ADR 0010 — Metrics on a separate listener, with bounded labels

**Status:** accepted
**Date:** 2026-08-07

## Context

Task 17 adds Prometheus metrics: request counts and latency by tool and
upstream, breaker state, errors by type. Two questions had to be answered before
writing any of it, and both have a wrong answer that is easier than the right
one.

**Where does `/metrics` live?** The obvious place is another route on the
gateway's own ASGI app. It is one line and no new machinery.

**What goes in a label?** A Prometheus time series exists for every distinct
combination of label values, and each one occupies memory in the metrics server
for as long as it is retained. Labelling by tool name is the natural thing to
want.

The second question has a sharp edge specific to this system. The tool name in a
`tools/call` is chosen by the *agent*, not by the gateway. An agent — buggy,
adversarial, or merely looping — that calls a hundred thousand nonexistent tools
mints a hundred thousand permanent time series. That is an unbounded memory
write into another process, available to anyone who can reach the gateway, at
the cost of one HTTP request each.

## Decision

**A separate listener**, `acp.admin`, bound to `127.0.0.1:9090` by default,
serving `/metrics` and a liveness `/healthz`. The gateway's own port serves only
`/mcp`.

**Every label value is bounded by something the gateway controls.** Tool names
are resolved against the catalogue; anything unrecognised becomes the single
value `unknown`. Arguments never appear. The histogram omits the tool label
entirely.

**Histogram buckets chosen against this system's timeouts**, reaching 60
seconds, rather than the library defaults which stop at 10.

**Breaker state is exported as a state set** — one series per state, exactly one
of them 1 — rather than a single gauge holding 0, 1 or 2.

## Alternatives considered

**`/metrics` on the gateway port.** Simpler, and it publishes every upstream
name, every tool name, the shape of the traffic and which dependencies are
currently failing — to anyone who can reach the component whose job is to sit
between agents and the things they can do. That is a reconnaissance report
served from the thing being protected. "We will firewall it in production" is
the sentence that precedes it being public. A second listener makes exposure a
deliberate act of configuration, which is the direction a security control
should fail in.

**A separate listener, but authenticated.** Better still, and it needs the
identity work of Phase 2 to exist first. Loopback-by-default is the version
available today and is not weakened by adding authentication later.

**Labelling by the requested tool name.** The version that reads most naturally
and is a denial-of-service vector against your own monitoring. Resolving against
the catalogue costs nothing and bounds the label by configuration rather than by
input.

**Dropping the tool label entirely.** Safe, and it throws away the answer to
"which tool is slow", which is most of why anyone reads these. Bounding it is
better than losing it.

**Keeping the tool label on the histogram too.** Buckets multiply: upstreams ×
tools × thirteen buckets is how a histogram becomes the largest object in a
metrics server. Counters carry the tool dimension; the histogram carries
upstream and method.

**A single numeric gauge for breaker state.** Smaller, and unreadable — nobody
remembers whether 2 means open, and the resulting queries have to be decoded
rather than read.

**Scraping breaker and bulkhead state at request time** rather than publishing
on change. More correct in principle for a gauge, and it requires reaching
through the retry wrapper into the guard from the admin app — plumbing a metrics
dependency through the registry to get at private structure. Transitions are
rare and slot changes are two integer writes, so publishing on change costs
nothing and keeps metrics a leaf dependency.

**The library's global registry.** The default, and it raises on duplicate
registration, which makes the collectors impossible to rebuild in one process
and leaks state between tests. A private `CollectorRegistry` avoids both — the
same mistake that let a tracing test leak an exporter into every test after it
(bug 17).

## Consequences

`acp serve` now runs two uvicorn servers in one task group. Both install their
own signal handling, so a Ctrl+C or SIGTERM drains both, and the admin listener
is told to exit when the gateway returns so it cannot hold the process open.
`ACP_ADMIN_ENABLED=false` runs without it.

Task 18's readiness endpoint lands on this app for free, which is half the
reason it exists now rather than later. Note that `/healthz` here is
*liveness only* and deliberately does not consult the upstreams: a liveness
probe that fails because a dependency is unhealthy gets the container restarted
for someone else's outage, turning one broken upstream into a crash loop across
every replica.

Metrics are recorded from four places — the client's single observation point,
the retry wrapper, the breaker's transition log, and the bulkhead's slot
accounting. Each was already the one place that saw the event, so nothing new
had to be threaded anywhere.

The scrape endpoint is deliberately outside the request-context middleware. A
scrape every fifteen seconds forever would otherwise produce a log line every
fifteen seconds forever, burying real traffic under monitoring of the
monitoring.
