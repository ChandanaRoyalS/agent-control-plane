# Demo — catching a rug pull

Every other failure this gateway handles announces itself. A timeout times out, a
broken upstream errors, a saturated one refuses. This one does not. Every request
in this demo succeeds, in single-digit milliseconds, with a well-formed response.

## Run it

Four terminals, or one with `&`. From the repository root:

```bash
# 1 — mock upstreams, clean
uv run python -m acp.mocks.mock_a &
uv run python -m acp.mocks.mock_b &

# 2 — the gateway, with drift detection on (the default)
uv run acp serve
```

Confirm there is nothing to report:

```bash
curl -s localhost:9090/schemas | jq
```

```json
{ "detecting": true, "baseline": true, "drift": false, "events": [], "counts": {} }
```

## Pull the rug

Stop mock A and bring it back with one environment variable changed. Nothing else
about it changes — same port, same tools, same handlers, same responses.

```bash
kill %1
MOCK_SCHEMA_DRIFT=description uv run python -m acp.mocks.mock_a &
```

Now wait one probe interval — fifteen seconds by default — and watch the
gateway's log. It has not received a single failed request:

```json
{"event": "schema.drift", "level": "warning", "upstream": "mock-a",
 "tool": "read_document", "kind": "description_changed",
 "before": "a3f21c9d0e4b", "after": "7c1e08b4d9aa",
 "detail": "mock-a__read_document: description changed (a3f21c9d0e4b -> 7c1e08b4d9aa)"}
```

And the same thing from outside the process:

```bash
curl -s localhost:9090/schemas | jq '.counts'
curl -s localhost:9090/metrics | grep schema_drift
```

```
acp_schema_drift_events_total{kind="description_changed",upstream="mock-a"} 1.0
acp_schema_drift_outstanding{upstream="mock-a"} 1.0
acp_schema_drift_outstanding{upstream="mock-b"} 0.0
```

## The point

Check what else noticed. Nothing did:

```bash
curl -s localhost:9090/readyz | jq '.ready'          # true
curl -s localhost:9090/metrics | grep 'outcome="ok"' # every call succeeded
curl -s localhost:9090/metrics | grep breaker_state  # still closed
```

The upstream is healthy by every measure this gateway had before task 20. It is
also now instructing every agent that reads its catalogue to fetch a document and
paste the contents into its next call.

## Acknowledge it, or don't

The alert fires once. The *state* persists until a human decides:

```bash
uv run acp schemas check          # exits 1, prints the change
uv run acp schemas capture        # records it as the new normal
git diff config/schema-baseline.json
```

That diff is the whole design. Acknowledging drift is a commit with somebody's
name on it, reviewed like any other change — not a file the gateway quietly
rewrote for itself while nobody was looking.

## Other flavours

`MOCK_SCHEMA_DRIFT` also takes `schema` (a new argument appears), `added` (a tool
called `exfiltrate` shows up), `removed`, and `all`.
