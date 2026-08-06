# ADR 0008 — Validate outbound requests against the spec, not against our mocks

**Status:** accepted
**Date:** 2026-08-06
**Amends:** [ADR 0004](0004-hand-roll-mock-protocol-layer.md), [ADR 0005](0005-hybrid-protocol-layer.md)

## Context

Task 15's demo pointed the gateway at its own inbound half — which is built on
the MCP SDK — and every request was rejected:

```
-32602  params._meta must be an object carrying the required
        'io.modelcontextprotocol/protocolVersion' and
        'io.modelcontextprotocol/clientCapabilities' envelope keys
-32020  mcp-method header does not match the request body's method
```

The outbound client had been sending a top-level `_meta` with bare keys
`protocolVersion` and `client`. That envelope does not exist. It was invented
early, the mock upstreams were written to accept it, and by task 15 there were
297 passing tests — none of which could fail, because both sides of every test
were ours.

Three rules were being broken or narrowly missed:

- The envelope belongs in `params._meta`, under namespaced keys. `params` is
  therefore mandatory even for a method that takes no arguments.
- `MCP-Protocol-Version`, `Mcp-Method` and (for name-bearing methods) `Mcp-Name`
  must be sent *and must agree with the body*. The agreement check is the point
  of the headers: a proxy authorizes on the cheap header, so a server that let
  the body disagree would be authorizing one method and executing another.
- `Mcp-Name` carries a tool name, and tool names come from upstreams the gateway
  does not control. A name that is not header-safe has to travel through a
  base64 sentinel codec. Sending it raw produces a header the server cannot
  compare and, for a name shaped like the sentinel itself, one it misparses.

## Decision

**The envelope is declared once, in `acp.upstream.envelope`**, and a conformance
test asserts every constant, the header codec, and complete requests produced by
the real client against the SDK's own `classify_inbound_request` ladder and its
`encode_header_value` codec.

**The mocks now validate inbound requests** with those same rules, so an
integration test cannot pass against a request shape a real server refuses.

## Alternatives considered

**Import the SDK's constants directly into `acp.upstream`.** The obvious fix,
and it would make drift structurally impossible. Rejected because ADR 0005 keeps
the outbound half free of the SDK, and that decision is still right for the
reasons given there. Pinning by test gets most of the benefit: drift becomes a
red CI run rather than a silent divergence, and it is caught at the same commit
that introduces it.

Worth being honest that this is the weaker guarantee of the two. If the outbound
half ever gains a second SDK-shaped concern, revisit — the argument for a
`Protocol`-free constants import gets stronger each time this file grows.

**Leave the mocks permissive and rely on the conformance test alone.** Cheaper,
and it re-creates the original failure mode one layer up: the conformance test
covers the requests it happens to exercise, while the mocks certify everything
else. Making the mocks strict means *every* integration test is now also a
conformance test.

**Build the mocks on the SDK's server so validation comes for free.** This is
what ADR 0004 rejected, and it is still rejected — chaos modes exist to emit
genuinely malformed responses, and a well-behaved SDK server prevents exactly
that. The amendment is a split that ADR 0004 did not draw: *responses* stay
hand-rolled so they can be broken deliberately; *requests* are validated
strictly, because leniency there buys nothing and hides real bugs.

**Compare our encoder to the SDK's only by round-trip.** Weaker than it looks.
The server compares the header it received against the body byte for byte, so a
different-but-valid encoding of the same string still fails. The test asserts
byte equality, and falls back to a round-trip assertion only for inputs where
the two implementations are permitted to differ.

## Consequences

`acp.mocks.server` now imports from `acp.upstream.envelope`. A mock importing
from the production package is a dependency worth noticing, and it is the right
one here: the alternative is a third copy of the constants, which is precisely
the mistake being fixed.

Every hand-built request in the test suite goes through `tests/integration/
helpers.rpc`, which attaches the envelope, and `headers_for`, which derives the
routing headers from the body rather than alongside it — so a test cannot assert
agreement between two things it wrote separately.

The mock's `JsonRpcRequest` no longer has a top-level `_meta` field, and
`extra="forbid"` means the shape this project used to send is now rejected by
its own mocks. That specific regression cannot return quietly.

The lesson generalises beyond this bug and is the reason for writing it down: a
mock that agrees with your client proves only that you wrote both. Any protocol
implementation needs at least one test where the authority is something you did
not write.
