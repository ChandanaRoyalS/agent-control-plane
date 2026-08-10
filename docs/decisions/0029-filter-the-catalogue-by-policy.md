# ADR 0029 — Filter the catalogue: a denied tool is never offered

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 34 made the gateway refuse a policy-denied `tools/call`. That is the
backstop, but it is reactive: the tool still appears in `tools/list`, the agent
still sees it, still reasons about it, still tries it — and only then is refused.
The refusal is correct but late, and a tool an agent can see is a tool an agent
can be talked into calling.

Task 35 is the proactive half: a tool the caller may not use is not shown at all.
The agent's prompt never contains it, so it is never offered to the model, never
selected, never attempted. This is the "only tell the agent about the doors it may
go through" idea the project is built around — remove the option rather than
police it.

## Decision

**`tools/list` returns only the tools the calling principal may call**, computed
by `visible_tools(policy, principal, tools)` — a pure function that keeps a tool
iff `evaluate` allows the principal to call it by its qualified name.

- **Visibility reuses the enforcement decision.** Filtering calls the same
  `evaluate` the enforcer does, keyed on the same qualified name
  (`<upstream>__<tool>`, ADR 0003) the merged catalogue already carries. So the
  list can never advertise a tool the call would refuse, nor hide one the call
  would allow — visibility and callability are the same predicate, not two that
  must be kept in step by hand.

- **Fail closed, exactly as enforcement does.** When a policy is loaded and the
  request has no principal, the catalogue is empty, not full. A loaded policy is
  an assertion that authorization applies; showing every tool to an unidentified
  caller would be the inverse of deny-by-default at the visibility layer. Filter
  in the handler, where both the principal and the parsed catalogue are in hand.

- **Order is preserved.** The catalogue's ordering is a prompt-cache decision
  (an agent's prompt carries this list; a list that reshuffles every turn busts
  the model provider's cache), so filtering removes entries without reordering
  the survivors.

- **Enforcement stays.** Filtering does not replace task 34 — it sits in front of
  it. An agent that learned a tool name from elsewhere, a replayed list, a bug in
  filtering: any of these can still produce a `tools/call` for a hidden tool, and
  the enforcer refuses it. Filtering is defence by construction; enforcement is
  the guarantee that makes hiding safe rather than merely tidy. Removing either
  would be a hole.

## Alternatives considered

**Filter and skip enforcement.** Rejected — hiding a tool from a list is not the
same as refusing to run it. A name is guessable, cacheable, nameable directly;
visibility is a usability and prompt-hygiene win, not a security boundary on its
own. The boundary is enforcement (ADR 0027); filtering rides on top of it.

**Return the full list but mark denied tools disabled.** Rejected. It leaks the
same thing the enforcement oracle rule forbids — that the tool exists and is
forbidden. An absent tool tells the agent nothing; a disabled one tells it there
is a door it cannot open, which is exactly the map an attacker wants.

## Consequences

- `src/acp/policy/filtering.py` holds `visible_tools`, exported from the package
  and unit-tested (visibility tracks callability, order preserved, per-principal,
  deny-default hides). `on_list_tools` calls it when a policy is configured.
- With no policy configured, the catalogue is unfiltered and the gateway behaves
  as before — filtering is opt-in with the policy, like enforcement.
- An integration test on the real auth path proves a denied tool is absent from
  `tools/list` and an allowed one present, the visibility counterpart to task
  34b's enforcement test.
- Phase 3's core is now complete: a policy is loaded, evaluated, enforced on call,
  and reflected in what the catalogue shows.

## References

- ADR 0027 — enforcement is the backstop (the guarantee filtering rides on)
- ADR 0028 — enforce on the real request path (the paired call-time control)
- ADR 0026 — the evaluator is a pure function (the shared decision)
- ADR 0003 — namespace upstream tools (the qualified name filtered on)
