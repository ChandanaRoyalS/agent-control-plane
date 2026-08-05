# ADR 0001 — Target the 2026-07-28 MCP specification only

**Status:** accepted
**Date:** 2026-08-10

## Context

The Model Context Protocol released a major revision on 2026-07-28 which
converted it from a stateful, bidirectional protocol into a stateless
request/response protocol. The `initialize`/`initialized` handshake and the
`Mcp-Session-Id` header were removed; each request now carries its own protocol
version, client identity and capabilities in `_meta`. The legacy HTTP+SSE
transport is deprecated.

The revision also added features that matter directly to a gateway:

- `Mcp-Method` and `Mcp-Name` HTTP headers, so a proxy can route, meter and
  authorize on tool name without parsing the request body.
- Multi Round-Trip Requests (`resultType: "input_required"` plus an opaque
  `request_state`), which give a stateless path to mid-call human approval.
- `ttlMs` and `cacheScope` on list responses, for catalog caching.
- Mandatory RFC 8707 resource indicators and RFC 9207 issuer validation.

Supporting both the old and new protocols would mean maintaining session
tracking, sticky backend routing and bidirectional stream multiplexing purely
for the legacy path.

## Decision

Implement the 2026-07-28 specification only. Reject requests declaring an
earlier protocol version with a clear error naming the minimum supported version.

## Alternatives considered

**Support both protocol versions.** Rejected. Session multiplexing is the single
largest source of complexity in a stateful MCP proxy, and it buys nothing here:
this is a new project with no installed base to keep working. The maintenance
cost would be paid on every subsequent feature.

**Target the older stable spec and migrate later.** Rejected. The new spec's
routable headers and resource indicators are load-bearing for the authorization
design rather than incidental, so building on the old spec would mean designing
around their absence and then redesigning.

## Consequences

The gateway is a plain HTTP request/response proxy with no session state, which
makes it horizontally scalable behind an ordinary load balancer with no sticky
routing.

Clients on older MCP versions cannot use the gateway. Accepted deliberately.

The project is coupled to a specification that is very new, so some ecosystem
tooling may not support it yet. Mitigated by owning the mock upstreams, which
means the test suite never depends on third-party conformance.
