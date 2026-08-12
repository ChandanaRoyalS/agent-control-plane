# ADR 0048 — An approval is granted to a call, not to a token

**Status:** accepted
**Date:** 2026-08-12

## Context

Phase 6 is human-in-the-loop approvals. Everything before it decides
automatically: policy allows or denies, budgets charge, the firewall screens.
This is the case where the right answer is that no rule should decide alone — a
destructive call, a production dataset, a refund above a threshold.

The 2026-07-28 revision gives this a shape with no session machinery (ADR 0001):
the gateway answers `resultType: "input_required"` with an opaque
`request_state`, and the client retries with it once the approval lands. Nothing
is held open and no connection is pinned.

The interesting problems are not in the protocol. They are in what an approval
*is*.

## Decision

### 1. `require_approval` is a policy effect, not a separate config file

ADR 0033 says each concern gets its own config file, and an `approvals.yaml`
listing gated tools would have followed it. Rejected, because it can only ever
say *"this tool needs approval for everybody"* and the interesting approvals are
never that coarse. *"Support agents may delete records, but a delete against a
production dataset needs a human"* is a statement about **who** may do **what to
which argument** — precisely what the policy language already expresses, down to
the argument (ADR 0031), in first-match-wins order (ADR 0026).

So `Effect` gains a third member and a narrow `require_approval` can sit in
front of a broad `allow`, which is how an operator thinks about it.

### 2. `Decision.allowed` stays a boolean

**This is the whole safety argument for how a third outcome was added to a
system that had two.**

Every existing consumer asks `if decision.allowed`. Making that field
three-valued would have turned each of those call sites into a truthiness bug —
`Verdict.APPROVAL` is truthy — to be found one at a time, in production, on the
paths that matter most.

Instead `allowed` stays a boolean and `requires_approval` is a separate flag,
with the invariant that they are never both true. A held call answers `False` to
every caller that has not been taught about approvals. **They fail closed by
construction, without being changed and without anybody having to remember to
change them.** `Decision.verdict` exists for the callers that do need the third
value, and they ask for it explicitly.

Exactly three places had to be taught, and each is a bug in a different
direction if it is missed:

- **The catalogue filter** now shows a tool that is *not denied* rather than one
  that is *allowed*. A gated tool must stay visible: the agent naming it is what
  triggers the approval. Hiding it would make the feature unreachable from the
  only client that could use it.
- **The pre-dispatch fast path** treats `require_approval` as permissible. Not
  doing so would be a **false refusal** of exactly the kind ADR 0043 exists to
  prevent — a call a human was about to approve, stopped at the header before
  anyone was asked, with no rule an operator could point at.
- **The decision log** emits `policy.approval_required` and records
  `decision: "approval"`. A held call and a refused one are different things to
  count and alert on; logging both as denials would make the approval flow
  invisible in the one record that is supposed to explain what happened. The
  simulator gains a matching `NEWLY_GATED` outcome, separate from `NEWLY_DENIED`
  because a denial breaks the caller and a gate merely slows them down.

### 3. An approval is granted to a *call*, not to a token

The obvious implementation stores "token X is approved" and lets the retry
through. **That is a privilege escalation with extra steps.** An agent asks to
delete the test dataset; a human reads "delete the test dataset" and approves;
the agent retries the same token with `dataset=production`. Nothing in the
protocol stops it — the approval was for a token, and the token is what came
back.

So every request records a **fingerprint** of exactly what was asked — subject,
actor, tool, canonicalised arguments — and the retry is re-fingerprinted and
compared. An approval that does not match the call in front of it is not an
approval.

This is the result-cache key problem (ADR 0035) pointing the other way. There,
too broad a key serves one caller's data to another. Here, too broad a
fingerprint lets one caller's approval authorise a different call. **Same shape,
opposite failure direction** — which is also why the two do not share an
implementation: a change made for the cache's direction (where being narrow only
costs a miss) would silently apply to the one where being broad escalates. They
carry separate version stamps and evolve apart on purpose.

A call whose arguments cannot be canonicalised is **refused outright**, not
merely un-cached. The cache's answer to an unencodable argument is "skip storing
and carry on"; here the only safe answer is to stop, because an approval that
cannot be bound to a call is an approval for anything.

### 4. The token is an opaque handle, and the state is server-side

A self-contained signed token would make the gateway genuinely stateless. It is
wrong: the approval **decision** is the thing being protected, and a decision
carried by the client is a decision the client can mint. Even setting forgery
aside, a self-contained token can be neither revoked nor spent once, and this
flow requires both.

So the token is 256 bits from `secrets`, never derived from the call, and the
record lives behind an `ApprovalStore`. The gateway stays stateless in the sense
ADR 0001 committed to — no session, no handshake, no sticky routing *for the
protocol*. An approval is durable business state, like a row in a database, and
calling it session state to preserve a slogan would be dishonest about what it
is.

### 5. Single use, and expiry is the default-deny

An approval that stays approved is one human's yes and unbounded deletes, so
`resolve` consumes it as part of returning "proceed" — inside the function
rather than at the call site, because a caller that must remember to spend it is
one that eventually does not, and that failure is silent.

Expiry is enforced **when the token is resolved**, not by a sweeper, so an
approval cannot be honoured late because a background job did not run. It is
checked *before* the state, so an operator who approves after the window closed
has approved nothing: "late" is a decision the caller does not get the benefit
of. `State` has no `EXPIRED` member for the same reason — a stored `EXPIRED`
would be a claim that something ran on time.

### 6. Every refusal is undifferentiated

Seven ways a retry stops — no token, unknown token, expired, fingerprint
mismatch, wrong subject, denied, already used — and the caller learns only that
it did not work. Distinguishing "expired" from "not yours" is an oracle a caller
can map one request at a time, the same argument `PolicyDeniedError` makes about
naming the rule. The reason travels on the `Resolution`, for the log.

## The honest cut

**The shipped store is in memory, per process, and unlike the rate limiter's
identical cut (ADR 0044) this one affects correctness rather than accuracy.** A
replicated gateway that answers `input_required` from one instance and receives
the retry on another cannot resolve the token, and the caller is refused a call a
human approved.

That is why `ApprovalStore` is a protocol of four operations with no assumption
about locality — `create`, `get`, `decide`, `consume` against a shared row. The
Redis or Postgres implementation is a class, not a redesign. It is stated here
rather than discovered, because an undeclared deviation is indistinguishable from
an oversight.

The store deliberately exposes no `put`. The one operation it must not offer is
"grant an approval" from anywhere the request path can reach; `decide` is the
only way in, and it is called by the operator side.

## Alternatives considered

**`approvals.yaml`, a tool-level list.** Rejected — decision 1. It cannot
express the approvals worth having.

**A three-valued `allowed`.** Rejected — decision 2. It converts a compile-time
concern into a runtime one at every existing call site.

**A signed self-contained token.** Rejected — decision 4. It puts the decision in
the hands of the party the decision is about.

**Approve the token, not the call.** Rejected — decision 3, and it is the bug
this ADR is named after.

**Hold the connection open until a human answers.** Rejected. It is the design
the 2026-07-28 revision removed the need for: it pins a connection, requires
sticky routing, and turns an operator's lunch break into a request timeout.

**A sweeper that expires requests in the background.** Rejected as the *primary*
mechanism — expiry must be right when nothing ran. A sweeper is a fine memory
optimisation later and must never be the thing the guarantee rests on.

## Consequences

- New `acp.approvals` (`record`, `store`, `flow`) — pure, clock-injected, no MCP
  types and no gateway, so the whole decision table is tested by advancing a
  number.
- `Effect.REQUIRE_APPROVAL`, `Verdict`, `Decision.requires_approval`,
  `decision_for` shared between the evaluator and the simulator.
- `enforce_call` returns the `Decision` rather than `None`. A held call is
  neither permitted nor refused, so it cannot be expressed by returning or
  raising.
- `visible_tools` filters on "not denied"; `could_ever_allow` treats approval as
  permissible; the log gains `policy.approval_required`; the simulator gains
  `NEWLY_GATED`.
- **Still to wire (task 54, part 2):** the request path itself — answering
  `input_required` with the token, and reading the token back off a retry. Both
  depend on the exact wire spelling the SDK uses for `resultType`/`request_state`
  and on where a client echoes it, which is measured against the installed SDK
  rather than guessed (this project's rule 4: measure somebody else's
  implementation before claiming conformance).
- Task 55 adds the operator channel and its configuration on top of `decide`.

## References

- ADR 0001 — target the 2026-07-28 spec only (where MRTR comes from)
- ADR 0015 — two identities, not one (why the fingerprint carries both)
- ADR 0026 — first match wins (how the third effect orders)
- ADR 0031 — argument-level rules (why a tool-level list is not enough)
- ADR 0035 — a result cache key that cannot serve the wrong person (same shape,
  opposite failure direction)
- ADR 0043 — authorize on the routing headers (the false-refusal risk)
- ADR 0044 — what the rate limiter does not do (the in-memory cut, declared)
