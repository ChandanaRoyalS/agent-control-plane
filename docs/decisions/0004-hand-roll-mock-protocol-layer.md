# ADR 0004 — Hand-roll the protocol layer in the mock upstreams

**Status:** accepted
**Date:** 2026-08-05

## Context

The gateway needs upstream MCP servers to proxy to. Depending on real
third-party servers for tests would make the suite slow, non-deterministic, and
dependent on network access — so we own the upstreams.

These mocks have an unusual requirement: their purpose is to be provoked into
misbehaving on demand. The gateway's resilience work (timeouts, retries with
jitter, circuit breakers, health-driven catalog withdrawal) and its error
taxonomy can only be tested against an upstream that can be made to hang, return
malformed JSON-RPC, return protocol errors, return oversized payloads, and drop
connections mid-response.

ADR 0002 commits the *gateway* to the MCP Python SDK. The question here is
narrower: what do the *mocks* build on.

## Decision

Build the mock upstreams on a hand-written JSON-RPC and MCP tool layer
(`src/acp/mocks/jsonrpc.py`) served over Starlette, rather than on the MCP SDK's
server class.

Field names are read directly off the installed SDK's `mcp.types` module —
`Tool.inputSchema`, `CallToolResult.content` / `isError`, `TextContent.type` /
`text`, `ListToolsResult.tools`, `ErrorData.code` / `message` / `data` — and
asserted in tests, so the mocks stay wire-compatible with real MCP clients.

## Alternatives considered

**Build the mocks on the MCP SDK server.** Rejected. A correct SDK server
validates and normalizes its output, which is exactly what the chaos modes need
to bypass. Producing deliberately malformed JSON-RPC through a library whose job
is to prevent that means fighting it, and the resulting test fixture would be
harder to reason about than the ~150 lines it replaces.

**Use a third-party public MCP server as the test upstream.** Rejected. Slow,
non-deterministic, requires network access in CI, and cannot be made to fail on
command.

**Record and replay real traffic (VCR-style cassettes).** Rejected for now.
Replay gives determinism but not controllable failure, and the recording would
have to come from somewhere — which is the problem we are solving. Worth
revisiting once the gateway talks to real upstreams.

## Consequences

The test suite runs with no network, no external process, and no real sockets:
tests drive the ASGI app in-process through `httpx.ASGITransport`. It is fast
and identical locally and in CI.

Chaos modes are selectable per request via the `X-ACP-Chaos-Mode` header, or
process-wide via the `CHAOS_MODE` environment variable, so one test can flip an
upstream between healthy and failing without restarting anything.

The hand-rolled layer could drift from the MCP specification. Mitigated by
asserting the exact wire field names in tests, and by the fact that the mocks
only implement `tools/list` and `tools/call` — the surface is small enough to
verify by reading.

`starlette` and `uvicorn` become development dependencies. The mocks live under
`src/` so they can be run standalone (docker-compose, manual probing), but
nothing in the gateway's runtime path imports them.

**One deliberate limitation.** The `disconnect` chaos mode raises after the
response has started, which the in-process ASGI transport surfaces to the
caller. That is the closest an in-process test can get to a genuine dropped TCP
connection, but it is not identical. True socket-level disconnect behaviour is
verified separately against a real uvicorn process.
