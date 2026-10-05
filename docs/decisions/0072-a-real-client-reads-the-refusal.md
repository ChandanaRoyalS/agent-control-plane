# ADR 0072 — A real client reads the refusal

**Status:** accepted; amends [ADR 0043](0043-authorize-on-the-routing-headers.md)
and the catalogue half of [ADR 0068](0068-a-restriction-is-cleared-only-by-a-value-it-can-read.md)
**Date:** 2026-10-05

## Context

Every integration test in this repository talks to the gateway through
`tests/integration/helpers.py`, which builds requests the way this project
believes a client builds them. The suite and the gateway agreed because the
same hands wrote both. The external review of v2.0 named the gap (item 5): no
test showed that a client nobody here wrote could use the gateway.

`tests/integration/test_official_client.py` closes it. It drives the gateway
with `mcp.client.Client`, the official Python SDK's high-level client, over the
SDK's own streamable-HTTP transport. Nothing from `helpers` is on the wire. The
test supplies only a bearer token, because a deployment's agent supplies only
that. It runs in-process (`httpx2.ASGITransport`) and offline.

The first run found three defects. None had been visible to the 2,212 tests
that already passed.

1. **A denial on the fast path told the agent the server had broken.** The
   SDK sends `Mcp-Method` and `Mcp-Name`, so a tool the policy denies outright
   is refused by the pre-dispatch check (ADR 0043) before the body is read.
   That check answered `403 {"error": "forbidden"}`. The SDK cannot read that
   body, so the agent received `-32603 Server returned an error response`: an
   internal error, which a retry policy retries. The same denial from the
   handler said `-32040` and `recoverable: false`. One policy decision had two
   answers, and the wrong one sat on the path a conforming client takes first.
2. **A held call from an older client failed as an internal error.** A client
   that connects with the initialize handshake (protocol 2025-11-25 and
   earlier) cannot receive `input_required`, which only exists from
   2026-07-28. The SDK could not serialise the result and answered `-32603
   Handler returned an invalid result`. Worse, an approval had already been
   created for an operator to decide, for a call nobody could resume.
3. **A tool with an argument-scoped rule vanished from the catalogue.**
   `visible_tools` asked the evaluator about each tool with an empty argument
   mapping. Under ADR 0031 this already hid a tool whose only grant was
   argument-scoped. Under ADR 0068, which makes a restriction catch a call that
   omits its argument, it also hid every tool with an argument-scoped `deny`
   in front of a broad `allow`. That is the README's own example policy. Calls
   to the tool with permitted arguments were still served, but an agent
   listing tools could never find it. `schema.py` had said the opposite since
   ADR 0031 ("a rule with `args` still makes its tool *visible*"), and no test
   checked it.

## Decision

- **The fast path's 403 carries the handler's JSON-RPC error.** The body is
  `{"jsonrpc": "2.0", "id": null, "error": {"code": -32040, "message": "this
  call was not permitted", "data": {"recoverable": false}}}`. The id is `null`
  because the body has not been read. JSON-RPC uses `null` for "a request I
  could not identify", and the streamable-HTTP client matches the error to the
  request it posted. The status stays 403 for the reason ADR 0043 gave. The
  message stays undifferentiated. A test now asserts that both layers give the
  client the identical error.
- **A held call from a pre-2026-07-28 client is refused before it is held,**
  with a new `ApprovalUnsupportedError` (`-32041`, `recoverable: false`). The
  message names the protocol revision that would let the client wait. No
  approval is created, and the chain records the decision as `denied`, not
  `held`. Saying that the call needs approval is not a new oracle: a
  2026-07-28 client is told exactly that by `input_required`. An unknown
  version is treated as one that cannot wait.
- **Visibility asks `could_ever_allow`.** This is the conservative question
  the pre-dispatch check already asked of the routing headers: could any
  arguments make this call permitted? It moves from `acp.policy.predispatch`
  to `acp.policy.evaluate` so that both callers import it from the
  evaluator. The catalogue and the fast path can no longer disagree.
- **The official client is a test dependency of record.** The new file covers
  discovery, the qualified catalogue, a served call, both refusal layers,
  ADR 0068's re-spellings, the SDK's automatic `input_required` loop, an agent
  that waits for an approval and then completes the call, a handshake-era
  client, and the audit chain.

## What the official client does with an approval

`Client.call_tool` resolves `input_required` by itself: it retries with
whatever the server asked for, up to `input_required_max_rounds`. The gateway
asks for nothing the client can supply (ADR 0048), so the loop retries the same
`requestState` and gives up with `InputRequiredRoundsExceededError`. That is the
right outcome. The call stays held, once, and the agent cannot approve it. An
agent meant to wait for a person calls
`client.session.call_tool(..., allow_input_required=True)`, keeps the
`requestState`, and calls again after the decision. The test that shows this is
the reference for anyone building an agent against this gateway.

## Alternatives considered

- **Answer the fast-path refusal as a 200 with a JSON-RPC error.** Every SDK
  reads that, and every proxy in the path then records a success. ADR 0043
  rejected it for that reason, and that reason still holds. The SDK reads a
  JSON-RPC error inside a 4xx, so nothing forces the trade.
- **Hold the approval for an older client anyway** and let it poll with a
  side channel. There is no side channel in the older protocol that an agent
  would use, and every such approval is an operator's time spent on a call
  nobody can resume.
- **Keep visibility on the evaluator and special-case argument rules.** That
  is a second reading of the policy, kept in step by hand. `could_ever_allow`
  already exists, is already proven by `make prove-predispatch`, and asks
  exactly the question a listing can answer.

## Consequences

- A tool whose grant or restriction depends on arguments is now **visible**
  where it was hidden. That is the documented behaviour. A deployment that
  relied on the hiding was relying on a defect: the calls were never refused
  by it.
- A client that read the old 403 body `{"error": "forbidden"}` sees a different
  body. The status is unchanged.
- A new error code, `-32041`. Under ADR 0058 that is a minor version.
- The pre-dispatch proof and its unit tests import `could_ever_allow` from its
  new home. Its semantics are unchanged.

## References

- ADR 0003 — qualified tool names
- ADR 0031 — argument-level rules
- ADR 0043 — authorize on the routing headers
- ADR 0048 — an approval is for a call, not a token
- ADR 0058 — what a version number promises
- ADR 0068 — a restriction is cleared only by a value it can read
- `tests/integration/test_official_client.py`
