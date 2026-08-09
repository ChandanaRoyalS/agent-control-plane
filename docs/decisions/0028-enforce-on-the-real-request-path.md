# ADR 0028 — Enforce on the real request path, and fail closed

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 34a built `enforce_call` — the pure decision that raises `PolicyDeniedError`
on a denied call — and proved it in isolation. Task 34b wires it in: the policy
is loaded at startup and `on_call_tool` enforces it before routing to an
upstream. This is the first task in Phase 3 where policy actually changes what
the running gateway does.

Two questions had to be answered to wire it safely.

**Where does the principal come from?** The handler needs the caller's identity
to evaluate a rule. It reads `current_principal()` — the same request-scoped
contextvar the authentication middleware already sets, the same one the identity
tests assert reaches a handler. Nothing new threads identity into the call path;
the enforcement point reads what auth already bound.

**What happens when a policy is loaded but there is no principal?** A loaded
policy means authorization is expected. Reaching `on_call_tool` with no principal
means either authentication is not configured, or it is and the request slipped
past — both are conditions under which permitting the call would be a bypass.

## Decision

**Enforce in `on_call_tool`, reading `current_principal()`, and fail closed.**

- The policy is loaded at startup in `gateway_from_settings`, beside
  `load_upstreams`, so a malformed policy fails the boot with a named file (ADR
  0025) rather than surfacing on the first call. It is threaded explicitly
  through `gateway_from_configs` → `build_app` → `build_server` as an optional
  parameter, defaulting to `None`, rather than held in a module global — the same
  "assemble the wiring in one place, pass it down" discipline the upstream
  factory follows. A startup-set global would be less code and the wrong shape:
  it hides a dependency the type system should show.

- When no policy is configured (`policy is None`), enforcement is skipped and the
  gateway behaves exactly as before. Policy is opt-in, like the validator and the
  protected-resource document, so every existing deployment and test is unchanged
  until a policy is supplied.

- When a policy **is** loaded and the request has **no** principal, the call is
  denied, not permitted. A loaded policy is an assertion that authorization
  applies; a missing principal at the enforcement point is a misconfiguration,
  and the safe resolution of a misconfiguration in a security control is to
  refuse. Fail closed.

- The denial reaches the wire as `PolicyDeniedError` (code `-32040`), rendered by
  the existing `to_mcp_error`. The deciding rule stays in the log; the caller
  learns only that the call was not permitted (ADR 0027).

**Tested on the real path.** The integration test sends a real signed token
through the real `AuthenticationMiddleware`, which binds the principal the
handler reads — nothing binds it by hand. A test that set the contextvar itself
would exercise a path production does not have, the same failure the
no-passthrough suite was built to avoid (ADR 0023). Allowed calls reach the
upstream; denied calls and the deny default return `-32040`; the rule name never
appears on the wire.

## Alternatives considered

**Skip enforcement when the principal is missing.** Rejected — it is the bypass
the fail-closed rule exists to prevent. "No identity, so no rule matched, so
allow" inverts deny-by-default at exactly the moment it matters.

**Enforce in the ASGI middleware instead of the handler.** Rejected. The
middleware does not know the tool name — that is in the JSON-RPC body the SDK
parses. Enforcing in `on_call_tool`, where both the principal and the parsed tool
name are in hand, keeps the decision at the one point that has everything it
needs, and leaves the middleware doing only authentication.

## Consequences

- `runtime.py` loads the policy and threads it down; `server.py`'s `on_call_tool`
  enforces it. Both are additive, keyword-only, `None`-defaulted — no existing
  caller signature breaks.
- Enforcement now runs on every `tools/call` when a policy is configured. The
  catalogue is not yet filtered — a denied tool still appears in `tools/list` and
  is refused only when called. Filtering it out so it never appears is task 35;
  this task is the backstop that makes filtering safe to add.

## References

- ADR 0027 — enforcement is the backstop (the primitive wired here)
- ADR 0025 — deny-by-default is structural (why a bad policy fails the boot)
- ADR 0023 — prove the invariant, then prove the proof (why the test uses the real auth path)
- ADR 0015 — two identities, not one (the principal the handler reads)
