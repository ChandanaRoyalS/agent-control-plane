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
