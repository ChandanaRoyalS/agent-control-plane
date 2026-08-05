# ADR 0005 — Hybrid protocol layer: hand-rolled outbound, SDK inbound

**Status:** accepted
**Date:** 2026-08-05
**Amends:** [ADR 0002](0002-use-mcp-python-sdk-v2-beta.md)

## Context

ADR 0002 committed the gateway to the MCP Python SDK v2 beta. Writing the
outbound client made it clear that decision was too coarse: the gateway's two
halves have genuinely different requirements.

**Outbound (gateway → upstream servers).** This side talks to servers that are
expected to be slow, broken, or hostile. It needs to set and read the
`Mcp-Method` and `Mcp-Name` headers for routing and pre-dispatch authorization
(task 35), own per-upstream connection pools and layered timeouts (tasks 13–14),
and — critically — *observe* a malformed response and classify it rather than
have a library raise or normalise it. An SDK client is designed to hide exactly
that machinery, and is built for an agent talking to a few well-behaved servers
rather than a proxy multiplexing many unreliable ones.

**Inbound (agents → gateway).** The opposite. Here the goal is being correct and
compatible with any MCP client that exists, and there is no reason to misbehave.
Protocol correctness inherited from the spec authors is worth more than control.

## Decision

Hand-roll the outbound client over `httpx` (`acp.upstream`). Use the MCP SDK for
the inbound server when task 9 lands.

## Alternatives considered

**SDK on both sides (ADR 0002 as written).** Rejected for outbound. Beyond the
control problem, the v2 beta cannot currently be installed in the environment
where this code is written and verified, so choosing it would mean shipping
unrun code into the most failure-sensitive part of the system.

**Hand-roll both sides.** Rejected for inbound. The one genuinely strong
argument for the SDK is that it *is* the reference implementation, and on the
inbound side we want maximum compatibility with clients we do not control.
Hand-rolling there would trade real safety for control we do not need.

## Consequences

We own protocol correctness on the outbound path. Mitigated by the mock fleet
being an independent implementation: `acp.mocks.jsonrpc` serialises and
`acp.upstream.models` parses, written separately, so agreement between them is
evidence rather than tautology. The `inputSchema` and `isError` aliases are
asserted from both directions.

We write our own OpenTelemetry instrumentation in task 16 instead of inheriting
the SDK's middleware, and implement multi-round-trip requests ourselves in task
54 if they are needed on the outbound path.

Two protocol implementations live in the codebase. Accepted: they face opposite
directions and have different requirements, and the boundary between them is the
gateway's own internal model rather than a shared wire type.

### Verified, not assumed

The outbound client's failure mapping was checked against a real `uvicorn`
server over real sockets, not only in-process:

- A hung upstream with a 1s read timeout raised `UpstreamTimeoutError`
  (`recoverable: true`) after 1.36s.
- A connection dropped mid-response produced httpx's
  `peer closed connection without sending complete message body`, mapped to
  `UpstreamUnavailableError` (`recoverable: true`).
- An unreachable port produced `All connection attempts failed`, mapped to
  `UpstreamUnavailableError`.

This matters because `httpx.ASGITransport` runs the app in-process with no
socket, so neither timeouts nor disconnects behave realistically there — the
limitation ADR 0004 records. The affected unit tests therefore use
`httpx.MockTransport` raising the exact exceptions a real socket produces, with
the real-socket behaviour above as the reference.
