# ADR 0067 — Record the dispatch before the dispatch

**Status:** accepted
**Date:** 2026-09-10

## Context

ADR 0050 §6 states the claim this gateway's audit trail rests on: **a call this
gateway cannot record does not happen.** ADR 0053 §1 repeats it. The request
path did not implement it.

`on_call_tool` called the upstream and chained `tool.called` afterwards. So a
failed audit write meant the side effect had already happened, the caller was
told the call failed, and the chain said nothing about it — the worst of the
three possible outcomes, because an omission asserts that nothing occurred and
ADR 0050 itself calls that "worse than none".

With no policy loaded there is no authorization record either, so a call could
reach an upstream having produced **no audit rows at all**.

Reproduced by counting dispatches at the transport, with a sink that fails only
on the tool-call record:

```
payload.error.code == AuditUnavailableError.code   # the caller is refused
dispatched == ['search']                           # and the tool ran anyway
```

The existing test asserted the refusal reaches the caller. Nothing asserted the
upstream was not reached, which is the half the claim is actually about.

## Decision

**Chain the tool-call record before the upstream is touched**, with outcome
`allowed`, and chain the outcome (`completed` or `failed`) after. An unwritable
record now refuses the call before anything external has happened.

Three records per tool call: *authorized*, *dispatched*, *completed*. They are
three different facts and only the first two can be recorded before they are
true. Keeping `authorization` separate stays right for the reason it always was:
"alice was allowed to search" is true even when a cache hit or a held approval
means the search never runs.

## Alternatives considered

**Fold the dispatch fact into the authorization record.** It already precedes
dispatch, so this is free, and it is wrong for the reason above — the
authorization record is true in cases where no dispatch happens, so reading it
as a dispatch would over-report every cache hit and every held approval as a
call that ran.

**Write-ahead only when no policy is loaded**, since that is the case with zero
records. Cheaper, and it makes the guarantee conditional on a configuration —
which is the opt-in-security pattern ADR 0061 argues against and ADR 0062 had to
be amended for. Twice in one release is enough.

**Accept the gap and log loudly.** The operational log is not the artifact
anybody audits, and a claim in an ADR that the code does not keep is the pattern
this whole release exists to remove.

**Make the post-dispatch write best-effort.** Tempting, because the call has
already succeeded by then and refusing the caller invites a retry. Rejected
because it silently reintroduces the same hole one record later, and because
`audit_required` is a deployment's stated choice about exactly this trade.

## Consequences

**This costs one more `fsync` per tool call, and that is not small.** ADR 0054
measures the audit `fsync` at 5.8 ms against a gateway overhead of 20.7 ms on
the miss path, so a third record is roughly a 28% increase in the gateway's own
fixed cost. That number has not been re-measured here — no Docker on the machine
this was written on — and it should be, by ADR 0054's harness, before anybody
quotes a new overhead figure.

The lever for a deployment that finds it too expensive already exists and is
documented: `ACP_AUDIT_FSYNC=false`, at the durability cost ADR 0053 measured.
The lever that does not exist, on purpose, is one that turns the write-ahead off
while leaving the claim in the documentation.

**A retry hazard is now explicit.** If the *post*-dispatch write fails, the
upstream has run and the caller is told the call failed. For a non-idempotent
tool a retry then performs the side effect twice. This is not new — it was the
behaviour before, for every failure — but it is now the only remaining case
rather than being hidden among worse ones, and it belongs in the threat model
rather than in this paragraph alone.

What would make us revisit: a measured overhead figure that makes the third
record untenable for a real deployment. The answer then is a batched or
group-committed audit write, not a return to recording effects after they
happen.
