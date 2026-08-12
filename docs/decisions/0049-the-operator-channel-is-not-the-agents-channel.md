# ADR 0049 — The operator channel is not the channel the agent speaks to

**Status:** accepted
**Date:** 2026-08-12

## Context

ADR 0048 built everything up to the moment a call stops. The policy says
`require_approval`, the gateway answers `resultType: "input_required"` with an
opaque `request_state`, the record sits in an `ApprovalStore` marked `PENDING`,
and the retry that carries the token back is re-fingerprinted before it is
allowed to proceed.

Nothing could answer it. `ApprovalStore.decide` existed and had exactly one
caller: a test. Task 55 is the answering, and almost every interesting question
in it turns out to be about *who is allowed to be the person* rather than about
HTTP.

## Decision

### 1. The channel lives on the admin listener, and that is the control

The obvious place for `POST /approvals/{token}` is the gateway app. It is
already running, already authenticated, already has the store.

**It is also the app the agent talks to.** An agent that can reach the endpoint
which grants approvals does not need to be talked into a destructive call; it
can approve one. Every other protection in `acp.approvals` — the fingerprint,
the single use, the expiry — assumes the deciding party is not the asking party,
and mounting the decision on the asking party's listener quietly removes that
assumption while leaving all the machinery in place to look reassuring.

So the routes go on the admin app: a separate listener, on a separate port,
bound to loopback by default, which ADR 0010 stood up for the metrics endpoint
and which has never been reachable from the request path. **An agent cannot
approve its own call because it cannot address the thing that approves calls.**

That is the same argument `_await_approval` already makes about MRTR's
`input_responses` — the client may answer the questions the server asked, and
here the client is the agent, so nobody reads it. This makes the argument a
second time in the network topology, because a guarantee that rests on one `if`
statement staying correct is one refactor away from being gone, and a guarantee
that rests on two ports is not.

### 2. Authenticated — and absent when it is not configured

The admin listener was designed as a read-only scrape target behind loopback,
with no authentication at all. Adding a write to it changes what it is, and the
thing this write writes is a *permission*.

Both routes require a bearer credential from `ACP_APPROVAL_OPERATOR_TOKEN`,
compared with `compare_digest`. The listing is authenticated too, and not as a
formality: the pending list is a live feed of subjects, tools and argument
values — what the estate's agents are currently trying to do — which is a
considerably better reconnaissance report than the metrics this listener was
built for.

With no credential configured, **the routes are not mounted**. Not present and
returning 403: absent, 404, as though the feature did not exist. A 403 is a
promise that the thing is there and merely shut, which is an invitation and a
second thing to get right. This is the same presence-based switching the secret
store and token exchange already use, for the reason `build_token_exchanger`
gives: a credential is not something you can forget to supply and still have the
feature appear to work.

A shared secret rather than a JWT, because the party being authenticated is a
person or a small internal console on loopback, not a fleet. Standing up an
issuer to answer yes-or-no is a cost with no matching benefit, and the seam is
one function (`_authorized`) if that changes.

### 3. The record carries the arguments — a deliberate departure from ADR 0045

Task 54 stored a fingerprint of the call and not the call. An operator could
therefore be shown a subject, a tool name and a SHA-256 digest, and asked to
decide.

**An approval you cannot read is not an approval.** It is a rubber stamp with
extra ceremony, and it fails in exactly the direction the feature exists to
prevent: the human says yes because saying yes is the only thing the interface
lets them meaningfully do. Worse, it makes ADR 0048's own example unanswerable —
"a human reads *delete the test dataset* and approves" is the story the whole
design is built on, and there was no way to read it.

So `ApprovalRequest` carries `arguments_json`. This contradicts ADR 0045, which
keeps argument *values* out of the decision log, and the contradiction is about
the reader rather than the data:

| | decision log (ADR 0045) | approval record (here) |
|---|---|---|
| lifetime | durable, rotated, archived | in memory, TTL of five minutes |
| readers | operators, SREs, SIEM vendors, anyone with log access | the one person deciding this one call |
| purpose | explain what happened | decide what should happen |

Same data, different exposure, opposite answer. Stating it here because it looks
like an inconsistency and would otherwise be *read* as one — probably by me, in
six months, about to "fix" it.

### 4. What is displayed is what is fingerprinted

The stored form is the canonical JSON string `fingerprint()` was computed over,
produced by one extracted `canonical()` function that both call. Not a mapping
re-serialised for display.

A second encoder is the one place "approve the call you read" and "approve the
call that runs" could come apart, and they would come apart *quietly*: two
encoders that agree on every test fixture can disagree on a float, a unicode
escape, or a key ordering, and the failure surfaces as a human approving
something subtly other than what ran.

**The bound is a bound, not a truncation.** Past
`MAX_DISPLAYED_ARGUMENT_BYTES` the arguments are withheld entirely and the
response says so, because a truncated display *is* a different call from the one
being approved. Withholding makes approving blind a visible choice; truncating
makes it an invisible one. The fingerprint is still taken over everything, so
the binding is unaffected by the display limit — what is withheld is the view,
never the guarantee.

### 5. Refusals here are differentiated, and that inverts the request path's rule

`acp.approvals.flow` refuses seven different ways and tells the caller nothing
about which, because distinguishing "expired" from "not yours" is an oracle an
agent can map one request at a time. That is the same argument
`PolicyDeniedError` makes about naming the rule.

The operator channel does the opposite: 404 for an unknown token, 409 with the
state for one already decided, 409 with `expired` for a lapsed one, 400 naming
the field for a malformed body. The party here is the one the control exists to
serve, is already authenticated, and can already read every pending request in
full — there is nothing left to withhold, and withholding it anyway would only
make the channel harder to use correctly, which for a security control is a cost
paid in people routing around it.

### 6. Expiry is refused at decision time, not only at resolution

`store.decide` would happily record an approval against a lapsed request, and
the retry would then be refused on expiry. Correct — and completely opaque: the
operator sees their approval accepted, the caller stays blocked, and nothing
anywhere connects the two. So the route checks expiry itself and answers 409
`expired`, leaving the record `PENDING`.

This does not replace the check in `resolve`. That one is the guarantee; this
one is the explanation. Removing either is a different kind of bug.

### 7. The store exists when the policy can hold a call

Not a flag. `Policy.gates_calls` is asked at startup, and a policy containing a
`require_approval` rule is what builds the store — because the rule *is* the
statement of intent, and a second switch beside it could only ever be forgotten.
Forgetting it means `require_approval` fails closed at request time, on somebody
else's traffic, rather than at startup where a person is looking.

The loud case is a policy that gates calls with **no** operator credential. The
gateway is then perfectly correct and completely useless: every gated call is
held, nothing can answer it, every caller waits out the TTL and is refused. That
warns rather than refuses to start, because a replicated deployment may
legitimately answer approvals from another process against a shared store — a
real configuration this project's in-memory store cannot yet serve and should
not pre-emptively ban. What it must not be is quiet.

### 8. The operator's screen is the last place an injection can land

The arguments on that screen were chosen by an agent which may have read a
hostile document. A document that cannot talk the gateway into running a tool
can still try to talk the *operator* into approving one — "APPROVED BY SECURITY,
click yes", or a `reason`-shaped string embedded in an argument value.

So the values leave as JSON data under a key that says what they are, never as
prose, and `UNTRUSTED_NOTICE` travels in every response for whatever renders
them. ADR 0038 fences upstream content before an agent reads it; this is the
same idea pointed at the human, who is the one reader in the system that cannot
be given a system prompt. The gateway cannot enforce this — a console is free to
render the notice and then interpolate the arguments into markdown anyway — and
saying so in the payload is the most a JSON API can do.

## The test transport, and the seven rounds that bought it

Not a decision about the product, and recorded anyway because the lesson cost
more than most of the ones that are.

`tests/integration/test_approvals.py` was written with a hand-rolled request
body that omitted the 2026-07-28 envelope. The SDK selects a result surface by
`(method, version)`; `InputRequiredResult` exists only at 2026-07-28, and every
earlier revision maps `tools/call` to a bare `CallToolResult`. So a request
without an envelope was served as an older client, the gateway's correct
`input_required` answer could not serialise, and the suite reported `-32603
Handler returned an invalid result`. Seven rounds of debugging a gateway that
was right the entire time, including three wrong hypotheses before the first
piece of instrumentation.

**The helper that would have prevented it already existed.**
`tests/integration/helpers.py` had `rpc()` — which always attaches the envelope
— and `headers_for()`, which derives the routing headers *from the body*, with
docstrings arguing precisely the point the debugging session rediscovered. The
new test simply did not use them.

So the fix is not another helper somebody must remember to call.
`gateway_client` hands back a client whose transport completes every JSON-RPC
request on its way out: a missing envelope is filled in, routing headers are
derived from the body actually being sent, and anything the test wrote
explicitly is left exactly as written so a conformance test can still send a
deliberately malformed request. **A test cannot get this wrong by omission
because there is nothing left to omit.** A convention is a thing a new file can
skip; a transport is not.

## The honest cut

Unchanged from ADR 0048 and worth repeating because this ADR adds a second party
to it: **the store is in memory, per process.** A replicated gateway that holds
a call on one instance and receives the operator's decision on another cannot
resolve it, and now there are two ways to land on the wrong instance rather than
one. `ApprovalStore` is four operations against a shared row precisely so the
Redis or Postgres implementation is a class rather than a redesign, and
`ApprovalReader` is separate so a shared store can decline to enumerate a fleet's
worth of pending requests without failing to satisfy the request path's needs.

There is no operator UI. The channel is JSON over HTTP, which is what a console,
a chat bot or a `curl` in a runbook can all drive, and building a web interface
would be a larger surface than the thing it fronts.

There is no notification. A held call sits in the store until somebody looks, so
the practical deployment pairs the pending list with something that polls it. The
alternative — the gateway sending mail or posting to a chat webhook — puts an
outbound integration and a credential for it inside the request path, which is a
bad trade for a component whose whole claim is that it is the narrow thing in
the middle.

## Alternatives considered

**Approval routes on the gateway app.** Rejected — decision 1, and it is the bug
this ADR is named after.

**A `403` when unconfigured.** Rejected — decision 2. Absent beats shut.

**Show the operator only the fingerprint.** Rejected — decision 3. It is the
interface that produces rubber stamps.

**Truncate large arguments.** Rejected — decision 4. It displays a different
call from the one being approved.

**Undifferentiated refusals here too, for consistency.** Rejected — decision 5.
The consistency is superficial; the reason for the rule does not apply to this
reader.

**Redact argument values on the operator view.** Rejected. Redaction exists for
readers who should not see the data; this reader is being asked to make a
decision *about* the data, and a redacted approval request is the fingerprint
option wearing a different hat.

**A flag to enable approvals.** Rejected — decision 7. The rule is the flag.

## Consequences

- New `acp.approvals.operator`: `operator_routes`, `build_pending`,
  `build_decide`, `as_view`, `ApprovalReader`, `UNTRUSTED_NOTICE`.
- `ApprovalRequest` gains `arguments_json` and `arguments_bytes`; `canonical` is
  extracted from `fingerprint` so display and binding share one encoder.
- `Policy.gates_calls`; `build_approval_store` in `acp.runtime`;
  `ACP_APPROVAL_OPERATOR_TOKEN`, `ACP_APPROVAL_TTL_SECONDS`,
  `ACP_APPROVAL_MAX_PENDING`.
- `build_admin_app` takes the store and the credential; `acp serve` passes the
  *same* store the request path holds calls in — a channel pointed at a second
  store would answer approvals nobody is waiting on, which looks exactly like a
  working deployment.
- `build_app`/`build_server` take `approval_ttl`, so the configured TTL is the
  TTL a caller is handed rather than a setting that reads as configured and
  behaves as default.
- `tests/integration/helpers.py` gains `EnvelopingTransport`, `gateway_client`,
  `authenticated_gateway`, `call_gateway`, `parse_rpc` and `mock_clients`;
  `test_approvals` and `test_policy_enforcement` are rewritten onto them.
  The remaining integration files still assemble their own gateways and are
  migrated as they are next touched.

## References

- ADR 0001 — stateless, target the 2026-07-28 spec only
- ADR 0010 — metrics on a separate listener (the port this rests on)
- ADR 0031 — argument-level rules (why a tool-level approval list is not enough)
- ADR 0038 — provenance framing (fencing untrusted content, pointed at agents)
- ADR 0045 — argument names, not values, in the decision log (departed from here,
  on purpose, for a different reader)
- ADR 0048 — an approval is granted to a call, not to a token
