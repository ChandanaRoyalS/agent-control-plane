# Captured output

Real responses from a running gateway, kept for the README and for spotting
regressions in wire format by eye.

## tools-list.json

A `tools/list` against the gateway with both mock upstreams running:

    uv run uvicorn acp.mocks.mock_a:app --port 9101 &
    uv run uvicorn acp.mocks.mock_b:app --port 9102 &
    uv run acp serve --port 8080

    curl -s -X POST http://127.0.0.1:8080/mcp \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python3 -m json.tool

Two things to notice. Both upstreams expose a tool named `search`; the client
sees `mock-a__search` and `mock-b__search` as distinct tools with *different*
schemas — mock-a takes `limit`, mock-b takes `channel`. Qualification renames
without homogenising.

And the schema key is `inputSchema`, camelCase, as the specification requires.
That value crosses four boundaries to get here: the mock serialises it, the
gateway's outbound client parses it to `input_schema`, the converter
re-serialises it into the SDK's model, and the SDK emits it. Two independent
implementations of the same wire format, agreeing.

## tools-list-one-upstream-down.json

The same request with `mock-a` killed:

    pkill -f "uvicorn acp.mocks.mock_a"

Three tools, not an error. One upstream failing does not take the catalogue
with it — the gateway serves what it can and logs the failure. A gateway that
went dark because one of five upstreams was down would be worse than one
serving the other four.

The gateway logs a warning naming the failed upstream while returning this.

Note the asymmetry: if *every* upstream fails the gateway raises instead of
returning an empty list. An empty catalogue is indistinguishable from a
correctly configured gateway with nothing attached, and would send the agent
off to attempt its task with no tools at all.

## `logging-breaker-lifecycle.jsonl`

A real run, captured from `ACP_LOG_FORMAT=json uv run acp serve` while an
upstream was killed and restarted. Two mock upstreams, six tools merged; then
`mock-a` is killed, four catalogue fetches follow, `mock-a` comes back, and one
final fetch happens after the breaker's 30-second reset.

Read it by following the `outcome` field. Four fetches against a dead upstream
at three attempts each would be twelve connection attempts. There are **five**:
the circuit opened on the fifth consecutive failure and the remaining seven
never happened. That ratio is the whole point of the breaker, and this file is
the evidence rather than the claim.

Two other things are visible in it. `gateway.upstream_degraded` carries
`served_tools: 3` on every line during the outage — the partial-failure policy
holding, so an agent connected at the time lost three tools instead of all six.
And the `error` field on those same lines changes from `UpstreamUnavailableError`
to `UpstreamCircuitOpenError`, which is the exact moment the gateway stopped
trying and started knowing.

Recovery is `breaker.opened` → `breaker.half_open` → `breaker.closed`, with a
single probe request deciding it. Every line carries the `request_id` the client
sent, so any one request can be followed end to end.

## `trace-fanout.txt`

One `tools/list` request, traced. A `SERVER` span at the root — created by the
MCP SDK's own middleware, which extracts its parent from `params._meta` — and
beneath it two `CLIENT` spans, one per upstream, created by this project's
hand-rolled outbound client.

The shape is the point. The two client spans are siblings, not a chain, because
the catalogue fan-out is concurrent; a reader can see at a glance which upstream
was slow. Each carries `acp.upstream`, `server.address` and `server.port`, so a
trace answers "which upstream" without anyone having to know which host is
which.

What is deliberately *absent* is as considered as what is present. No tool
arguments and no results: those attributes are opt-in in the GenAI conventions
because they routinely carry queries, identifiers and occasionally credentials,
and a span goes somewhere with a different audience and retention policy than
the gateway's logs. Failures record `error.type` and a fixed description rather
than the exception message, for the same reason.

The trace context reaches upstreams in `params._meta` under a bare `traceparent`
key — a documented exception to MCP's namespacing rule (SEP-414), made
explicitly so traces do not break between implementations that disagree about a
prefix.

## `metrics-during-an-outage.txt`

A Prometheus scrape taken after the same outage the breaker capture describes:
`mock-a` killed, four catalogue fetches, then restarted and recovered.

Worth reading alongside `logging-breaker-lifecycle.jsonl`. Both files report the
same event by different mechanisms and agree on the number that matters — five
connection attempts where twelve would have happened without a circuit breaker.
One is a narrative, the other is a counter; neither was derived from the other.

The labels are as considered as the values. `tool="none"` marks a method that
runs no tool; a tool name not present in any catalogue would collapse to
`unknown`, because the name in a `tools/call` is chosen by the agent and a label
value chosen by a caller is an unbounded write into the metrics server's memory.
The histogram omits the tool dimension entirely, since buckets multiply.

Served on a separate listener bound to loopback (ADR 0010) — this output names
every upstream, every tool and every currently-failing dependency, which is not
something to hand to whoever can reach the gateway.
