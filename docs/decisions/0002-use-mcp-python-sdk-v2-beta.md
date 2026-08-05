# ADR 0002 — Use the MCP Python SDK v2 beta, pinned exactly

**Status:** amended by [ADR 0005](0005-hybrid-protocol-layer.md)
**Date:** 2026-08-10

> **Amendment (2026-08-05):** this decision was too coarse. The gateway's
> outbound and inbound halves have different requirements, and only the inbound
> half uses the SDK. See ADR 0005.

## Context

Two versions of the MCP Python SDK are available. v1.x is stable but implements
the pre-2026-07-28 stateful protocol. v2 is in beta, implements the 2026-07-28
specification, renames the server class from `FastMCP` to `MCPServer`, moves all
fields to snake_case, unifies the client interface behind a single `Client`
class, and ships OpenTelemetry middleware enabled by default with W3C trace
context propagation.

ADR 0001 commits this project to the 2026-07-28 specification, which v1.x cannot
speak.

## Decision

Use the v2 beta, pinned to an exact version in `uv.lock`. Upgrade deliberately,
reading the changelog, rather than by floating a version range.

## Alternatives considered

**Use v1.x stable.** Rejected — it cannot implement the target specification, so
this would contradict ADR 0001.

**Implement JSON-RPC and the MCP message types by hand.** Rejected for the
protocol layer: it is a large amount of undifferentiated work that would consume
the project's time budget without teaching anything the project is about. We do
read the raw wire format in the MCP Inspector, because a protocol you have never
watched move is a protocol you cannot debug.

**Float the version (`>=2.0.0b1`).** Rejected. Beta APIs move, and an unpinned
beta means CI can break on a morning when nothing in the repository changed.

## Consequences

The gateway is on the current protocol from day one, and inherits OpenTelemetry
instrumentation with trace context propagation rather than building it.

The SDK is beta, so APIs may change between releases. Accepted, and mitigated by
the exact pin plus the mock upstream fleet, which makes an SDK upgrade a
contained, testable change rather than an unbounded one.

Upgrades become a deliberate task with a changelog read attached, not an
automatic resolution.
