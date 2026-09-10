# ADR 0062 — An approval names the person who gave it

**Status:** accepted
**Date:** 2026-09-10

## Context

`build_decide`'s docstring says the row an investigation wants is *"who approved
the delete, and what did they say they had checked"*. The row it wrote could
answer the second half:

```python
audit.record(
    AuditCategory.APPROVAL, "approval.decided",
    subject=decided.subject, tool=decided.tool, rule=decided.rule,
    outcome=..., reason=answer.reason or None,
    detail={"fingerprint": decided.fingerprint, "request_state": decided.token},
)
```

Three defects, in ascending order of seriousness.

**No operator identity.** The channel is authenticated by one shared bearer
token (`ACP_APPROVAL_OPERATOR_TOKEN`), so the record says that somebody holding
it said yes. Where four people hold that credential, the chain narrows an
incident to four people, and the free-text `reason` — written by whoever is
explaining themselves — is the only thing distinguishing them. For the one row
in this system describing a thing a *person* did, that is the wrong answer.

**The live approval token is in the record.** `request_state` is `decided.token`:
a 256-bit credential that is still spendable at the moment it is written, in
clear, into a file that outlives the approval it grants, under a key the
redactor's fragment list does not match. The fingerprint next to it already
identifies the call durably and grants nothing.

**The decision was committed before it was recorded.** `store.decide(...)` ran,
then `audit.record(...)`. A sink that raises therefore leaves a **live approval
with no record of it** — the exact outcome an audit log exists to make
impossible. And `record` rather than `arecord` means an `fsync` on the event
loop, which is the bug ADR 0053 removed from the request path and left here, and
means `_publish` never runs, so approvals never appeared on the trace console.

## Decision

**The credential identifies a named operator, and the name goes in the chain.**
`ACP_APPROVAL_OPERATORS_FILE` carries one credential per person;
`OperatorDirectory.resolve` returns *who* rather than *whether*, comparing every
candidate with `compare_digest` and not stopping at the first hit, so the
matching operator's position does not leak through response time. Credentials
are refused below 32 characters — the channel they open shows every argument of
every held call, and the shipped `dev-only-operator-token` was 23.

A deployment with one shared token still works and records the operator as
`shared`, with a warning at startup. Neither empty nor a plausible name: empty
reads as "not populated yet", and a name would be a lie. `shared` states exactly
what is known.

**`request_state` is gone from the record.** The fingerprint stays.

**The write is ahead of the decision.** `await audit.arecord(...)` runs first
and `store.decide(...)` follows; a failed write returns 503 and the call stays
held. If the write succeeds and the decision then fails, the chain holds a
decision with no downstream effect — visible, and reconcilable. An approval with
no row is invisible, and that asymmetry is the whole argument for write-ahead.

## Alternatives considered

**Sign each operator's answer, rather than authenticating a channel.** Genuinely
better: a signature binds the decision to a key rather than to a bearer token
somebody can paste into Slack. It also needs an issuer, a key distribution
story, and a revocation story for a channel whose users are a handful of people
on loopback. Named bearer credentials get from "somebody" to "alice", which is
the whole distance this defect is about; the next step is a real one and is
named in the threat model rather than pretended at here.

**Record the operator from a header the client supplies.** `X-Operator: alice`.
Self-asserted identity in an audit record is worse than no identity, because it
looks like evidence.

**Keep committing before recording, and retry the write.** A retry loop does not
change the failure — it widens the window in which the approval is live and
unrecorded, and does it under load, which is when the sink is failing.

**Record after deciding but refuse to *consume* without a record.** Splits one
decision across two states and leaves a decided-but-unrecorded approval sitting
in the store. Write-ahead has one state and one order.

## Consequences

Breaking for a compose stack or deployment using the short shared token. The
compose file now mounts `config/operators.compose.yaml` with two named dev
operators, which also makes the demo show a name.

Approvals reach the trace console for the first time, because `arecord`
publishes and `record` never did.

The `shared` fallback means the improvement is opt-in for existing deployments,
which is a real limit: a deployment that ignores the startup warning gets the
old attribution with a better-named field. The alternative was refusing to start
on a configuration that works today, for a defect that is about the quality of
evidence rather than about access.

What would make us revisit: an operator population large enough that credential
distribution is the problem rather than attribution — at which point the answer
is the signature scheme above, not more bearer tokens.
