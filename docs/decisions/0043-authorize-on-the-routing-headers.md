# ADR 0043 — Authorize on the routing headers, in one direction only

**Status:** accepted
**Date:** 2026-08-12

## Context

The 2026-07-28 revision added two routing headers, `Mcp-Method` and `Mcp-Name`,
so that an intermediary can tell what a request is *for* without parsing the
JSON-RPC body. This gateway is the exact component those headers were added
for — it sits between agents and upstream servers and its whole job is deciding
which calls proceed — and until now it read them only on the outbound side
(`acp.upstream.envelope`), never on the inbound one.

Reading them inbound buys two things. The cheap one is latency: a call no rule
could permit is refused without deserialising a body, validating it against the
schema, or resolving an upstream. The one that matters is attack surface. Today
a forbidden call is refused by `enforce_call`, which runs *after* the body has
been parsed and validated — so an attacker with no permissions still gets the
parser, the validator and the dispatcher to run on bytes they chose. Refusing at
the header means an unauthorized caller reaches strictly less code.

The obvious objection is the whole problem: **the headers are written by the
caller.** They are a claim, not a fact, and nothing reconciles them with the body
at this point in the stack because the body has not been read.

## Decision

**The pre-dispatch check may refuse, and may never authorize.**

That single direction is the entire safety argument. Anything decided in the
caller's favour on the strength of a header is decided on the attacker's
say-so; anything decided *against* them is decided on a claim they made
themselves. So the check only ever subtracts. What it does not refuse proceeds
to `enforce_call`, which reads the body and remains authoritative (ADR 0027 —
enforcement is the backstop).

A lying header is therefore worthless, and this is worth spelling out because it
is the reason the module contains no header-versus-body reconciliation:

- Allowed tool in the header, forbidden tool in the body → passes this layer,
  refused by the real one. Nothing gained.
- Forbidden tool in the header, allowed tool in the body → refused here. The
  attacker has refused themselves.
- No headers at all → nothing to decide, request proceeds to the real check.

There is no combination that buys a call. The desync a reconciliation check
would defend against cannot be exploited, so the check would be code carrying
its own bugs in exchange for nothing.

**And the question asked is not "would this be allowed".** A rule that
constrains an argument cannot match a call whose arguments are unknown — and at
header time they are always unknown, because the body is precisely what has not
been read. An implementation that evaluated the policy with an empty argument
mapping would refuse every call permitted by an argument-scoped rule (ADR 0031):
a false denial of legitimate traffic, produced by an optimisation that was
supposed to be invisible. The failure would be intermittent, would depend on the
shape of the policy rather than the request, and would look like a policy bug to
whoever hit it.

So the check asks the strictly weaker question **"could this ever be allowed,
for any arguments at all"** — `could_ever_allow`, a conservative reading that
walks the rules in document order (first match wins, ADR 0026):

- an **allow** matching on identity and tool, argument-constrained or not, means
  some call could be permitted — stop, do not refuse;
- a **deny with no argument constraints** matches every call to this tool by
  this principal, so no argument can rescue it — stop, refuse;
- a **deny that constrains arguments** decides only the calls whose arguments
  match it, and the rest fall through — keep walking;
- falling off the end is the deny default (ADR 0025) — refuse.

The identity-and-tool half of the match is `matches_without_arguments`, split
out of `_rule_matches` and shared with the real evaluator, so the fast path and
the authoritative path cannot come to disagree about who a rule applies to.
That is ADR 0030's rule ("one evaluator, two paths") applied to a third path.

## The invariant, and how it is checked

*If `could_ever_allow` says no, `evaluate` says no for every argument mapping.*

A false refusal here is the one failure mode that matters, because it breaks a
legitimate caller in a way no policy explains — intermittently, depending on the
shape of the policy rather than the request. So it is checked by search rather
than by argument, in `scripts/prove_predispatch.py` (`make prove-predispatch`),
which does three things because the first alone would prove nothing:

1. **Search for a counterexample.** 30,000 generated policies; every call the
   pre-check would refuse re-evaluated against every argument mapping a caller
   could send. 163,862 refusals, **655,448 re-checks, 0 false refusals**.
2. **Check the search has teeth.** The same search re-run against three broken
   readings — evaluate-with-empty-arguments (the trap), deny-wins-anywhere (the
   design ADR 0026 rejected), and argument-scoped-deny-settles-the-tool (the
   real thing with one guard removed). All three are caught, so the clean result
   above is a result rather than a blind spot.
3. **Break the header reading in source.** The two false-refusal modes that a
   search over policies cannot see — deciding methods whose name is not a tool,
   and matching an encoded name raw — are mutated into the file and the unit
   suite is required to notice, using the same in-place-edit machinery as
   `mutate_result_cache.py`.

Unit tests assert the same properties directly on the cases built to break them.

## Alternatives considered

**Trust the headers and skip the body check.** Rejected — this is the version
where the headers are load-bearing, and they are attacker-controlled. It turns a
performance optimisation into an authorization bypass.

**Reconcile header against body and reject mismatches.** Rejected as unnecessary
given the one-direction rule, per the case analysis above. It also has a real
cost: a client that sets headers slightly differently from its body (a proxy
rewriting a name, a retry with a stale header) would be refused for a
discrepancy that cannot harm anything.

**Evaluate the full policy with empty arguments.** Rejected — this is the trap.
It silently denies argument-scoped allows.

**Fail open when no principal is bound.** Rejected — a loaded policy with no
authenticated principal is a misconfiguration, and it is refused here for the
same reason `on_call_tool` refuses it rather than permitting it.

**A JSON-RPC error inside a 200.** Rejected — this happens before anything
parses a body, so there is no JSON-RPC request to answer; and a 200 tells every
proxy in the path that the request succeeded. 403, for the same reason
`AuthenticationMiddleware` answers 401.

## Consequences

- New `acp.policy.predispatch`: `could_ever_allow`, and
  `PreDispatchAuthorizationMiddleware` as raw ASGI (not `BaseHTTPMiddleware`,
  which runs downstream in a separate task and would defeat the point of
  refusing before dispatch).
- `matches_without_arguments` becomes public in `acp.policy.evaluate`, named for
  what it answers rather than for who calls it.
- The middleware is added to `build_app` **first**, so it is innermost: Starlette
  inserts at the front of the stack, so first-added runs last on the way in —
  inside `AuthenticationMiddleware`, which is what makes the principal available.
- The refusal is undifferentiated (`{"error": "forbidden"}`, naming neither rule
  nor tool), matching `PolicyDeniedError`. Naming either is an oracle a caller
  can map one request at a time.
- A refusal is logged at INFO with subject, tool and reason, so a fast-path
  denial is as visible in the decision record as a slow-path one.
- New `scripts/prove_predispatch.py` and a `make prove-predispatch` target,
  joining `prove-passthrough`, `prove-cache` and `prove-refusal` as the
  invariants this project checks by attacking them rather than by asserting
  them once.
- **Only `tools/call` is decided here**, though `NAME_BEARING_METHODS` lists
  three methods. That mapping answers "which methods carry an `Mcp-Name`", which
  is the right question on the outbound side and the wrong one here: the name on
  `resources/read` is a URI and the name on `prompts/get` is a prompt, and
  neither is a thing a policy rule is written about. Checking either against
  tool-shaped rules would find no match, hit the deny default, and refuse a
  request the real check permits — the same false refusal the argument trap
  above produces, arriving by a different door. Membership in the mapping is
  still asserted, so a method removed from it cannot silently keep being decided
  here.
- **The name is decoded before it is matched.** A tool name outside visible
  ASCII travels base64-wrapped in the codec's sentinel (`encode_header_value`),
  and matching the wrapper against a policy rule would refuse a legitimate call
  for the crime of having an awkward name — and upstream tool names come from
  servers this gateway does not control. `decode_header_value` is the codec the
  outbound client and the mock server already share, so all three agree on what
  a header says by construction. It answers `None` for a malformed sentinel
  rather than raising, which lands in the decline path below.
- **Anything unreadable is declined, not refused.** A header longer than 1 KiB,
  one that is not ASCII, a malformed sentinel, or the same routing header sent
  twice — each causes the layer to decline to decide. This layer acts only on a
  positive proof, and none of those is one; the request proceeds to the checks
  that read the body. Declining costs a fast path, and the alternative in the
  repeated-header case is guessing which of two names the body will agree with.
- `tools/list` names no subject to authorize, so it is untouched here; catalogue
  filtering (ADR 0029) handles it, and needs the body.

## References

- ADR 0025 — deny by default is structural
- ADR 0026 — the evaluator is a pure function (first match wins)
- ADR 0027 — enforcement is the backstop (why this may only subtract)
- ADR 0030 — one evaluator, two paths (why the matcher is shared, not copied)
- ADR 0031 — argument-level rules (the rules that make the naive version wrong)
