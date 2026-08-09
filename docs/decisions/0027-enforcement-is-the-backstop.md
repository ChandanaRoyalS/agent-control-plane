# ADR 0027 — Enforcement is the backstop, and it is pure

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 33 gave the policy a decision: `evaluate(policy, principal, tool)` returns
allow or deny. Task 34 acts on it — a denied `tools/call` must be refused. This
ADR covers the enforcement primitive (`enforce_call`) and the error it raises;
wiring it into the request path is task 34b.

There are two ways a forbidden tool can be kept from executing, and they are not
alternatives — they are layers:

- **Filtering** (task 35): a tool the caller may not use never appears in
  `tools/list`, so the agent never offers it and never calls it. This removes the
  attack surface by construction.
- **Enforcement** (this task): even a tool that was filtered out can still be
  named directly in a `tools/call` — an agent that learned the name elsewhere, a
  replayed request, a bug in filtering. Enforcement is what stops the call from
  running regardless of whether it was offered.

Enforcement has to come first, because filtering without it is unsafe: hiding a
tool from a list is not the same as refusing to run it. Enforcement is the
guarantee; filtering is the refinement that means the guarantee is rarely
exercised.

## Decision

**`enforce_call(policy, principal, tool)` is a pure function that allows silently
or raises `PolicyDenied`.** It calls `evaluate` and translates a denial into a
refused call. It is the whole of the enforcement logic, and — like the
subject-token invariant (task 27) — the request path will call it in exactly one
place, so the decision lives in a tested module and the SDK handler holds only
the call.

`PolicyDenied` is an `ACPError` (code `-32040`, a new range for policy) so the
existing `to_mcp_error` renders it as a JSON-RPC error with no new machinery.

**`recoverable` is false.** Unlike an expired token, a denial is not transient:
the principal is not entitled to this tool, and retrying the identical call is
refused identically. The correct agent behaviour is to stop, not to back off —
and `recoverable` is the field that tells it which.

**The denial names its rule in `details`, not to the caller.** The deciding rule
(or `None` for the deny default) is carried for the audit log. The caller-facing
message says only that the call was not permitted. Telling an agent *which* rule
denied it, or that a tool exists but is forbidden, is an oracle it can query one
request at a time — the same reason `AuthenticationError` strips its reason before
the wire. Once task 35 filters denied tools from the catalogue, the honest answer
to the caller is simply that no such tool is available.

## Alternatives considered

**Enforce inside `registry.call_tool`.** Rejected. The registry's concern is
routing — find the upstream, call it. Authorization is a different concern, and
folding "may I" into "where does this go" is the entanglement the resilience
layering (ADR 0006) and the identity split both avoid. A separate enforcer keeps
each concern testable on its own.

**Return a bool instead of raising.** Rejected. Every caller would have to
remember to check it, and the one that forgets is a silent authorization bypass.
Raising makes the safe path the default path: a denied call cannot proceed by
omission.

## Consequences

- `src/acp/policy/enforce.py` holds `enforce_call`; `PolicyDenied` joins the
  exception taxonomy. Both are exported from the policy package.
- Fully unit-tested: allow-returns, deny-raises, deny-by-default, non-recoverable,
  and the no-oracle property that the message does not reveal the rule.
- Nothing calls `enforce_call` yet. Loading the policy at startup and invoking the
  enforcer in `on_call_tool` — threaded explicitly through the gateway factory
  rather than via a startup-set global, per the "assemble in one factory" pattern
  — is task 34b.

## References

- ADR 0026 — the evaluator is a pure function (the decision this enforces)
- ADR 0025 — deny-by-default is structural (the default a denial reports)
- ADR 0006 — resilience as ordered wrappers (why authorization is not folded into routing)
