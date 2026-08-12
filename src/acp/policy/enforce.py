"""Enforce a policy decision in the request path, and record it either way.

Task 33's ``evaluate`` decides; this turns a denial into a refused call. It is
the backstop the whole model rests on — even once catalogue filtering removes
denied tools so they are never offered, a caller can still name a tool directly,
and this is what stops the call from executing. Filtering is defence by
construction; enforcement is the guarantee behind it.

**Every decision is recorded, not only the refusals.** That was the intent from
the start — ``Decision.rule`` exists because "a decision nobody can attribute to
a rule is a decision nobody can explain" — but only the denial path was wired,
and an allow returned silently. Three things depend on the other half:

- The **hash-chained audit log** covers every authorization decision. A chain
  built over refusals alone would faithfully prove the integrity of a record
  that is missing everything that actually happened.
- The **policy simulator** replays recorded traffic against a proposed policy to
  report what would change. Its input is this log; with allows missing, a
  simulation could only ever report denials that stopped being denials.
- An auditor's first question is never "what was refused". It is **"what did
  this agent do"**, and a gateway that cannot answer that from its own records
  is not an audit trail, it is an error log.

Kept as a pure function with the request path calling it in exactly one place,
the same shape as the subject-token invariant: the decision logic is here and
testable, and ``server.on_call_tool`` holds only the one-line call.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from acp.exceptions import PolicyDeniedError
from acp.identity.principal import Principal
from acp.policy.evaluate import Decision, Verdict, evaluate
from acp.policy.schema import Policy

logger = logging.getLogger(__name__)

ALLOWED_EVENT = "policy.allowed"
DENIED_EVENT = "policy.denied"
APPROVAL_EVENT = "policy.approval_required"

_EVENTS = {
    Verdict.ALLOW: ALLOWED_EVENT,
    Verdict.DENY: DENIED_EVENT,
    Verdict.APPROVAL: APPROVAL_EVENT,
}


def _record(
    decision: Decision,
    principal: Principal,
    tool: str,
    arguments: Mapping[str, object],
) -> None:
    """Write one authorization decision to the log.

    One function for both outcomes, deliberately. Two call sites emitting
    near-identical dictionaries is how an audit record acquires a field on one
    path and not the other — and a record whose shape depends on the outcome is
    one no query can group by.

    **Both identities are named.** The subject is who the work is for; the actor
    is which agent did it. This project's entire authorization model is that
    those are different questions, so a decision record carrying only the human
    would answer "was alice allowed to do this" while leaving "which of the four
    agents acting for alice did it" unanswerable — which is the question that
    matters when one of them is misbehaving.

    **Argument names, never argument values.** The names come from a tool's
    schema; the values are the user's data, and a `doc_id` is as likely to be a
    patient record as a public page. Writing values here would put exactly the
    payload this gateway exists to control into a log that a dozen people and
    three vendors can read — which is why ``redact`` exists and why this does
    not lean on it. The names alone are not decorative: they let the policy
    simulator (ADR 0045) settle a rule constraining an argument the call never
    sent, because a missing argument is not a match (ADR 0031). A rule
    constraining ``doc_id`` cannot have fired on a call that sent no ``doc_id``,
    and that is a *definite* answer recovered without recording anything
    sensitive.

    Sorted, so two records of the same call are byte-identical and a diff over
    the log shows changes rather than dictionary ordering.
    """
    logger.info(
        _EVENTS[decision.verdict],
        extra={
            "subject": principal.subject,
            "actor": principal.actor.subject if principal.actor else None,
            "tool": tool,
            "rule": decision.rule,
            "decision": decision.verdict.value,
            "reason": decision.reason,
            "argument_names": sorted(arguments),
        },
    )


def enforce_call(
    policy: Policy,
    principal: Principal,
    tool: str,
    arguments: Mapping[str, object] | None = None,
) -> Decision:
    """Allow the call to proceed, or raise ``PolicyDeniedError``.

    Returns the ``Decision`` when the policy permits ``principal`` to call
    ``tool``, or holds it for a human (ADR 0048). On a denial — an explicit deny
    rule, or no rule matching, which is the deny default — raises
    ``PolicyDeniedError``.

    **The return type changed from ``None`` when approvals arrived, and the
    caller must read it.** A call held for approval is neither permitted nor
    refused, so it cannot be expressed by returning or raising. Every caller
    that predates approvals still gets the old behaviour for the old two
    outcomes; a caller that wants the third has to ask for it.

    Both outcomes are logged at INFO before either returns or raises, so the
    record exists whatever happens next. INFO rather than DEBUG on purpose: this
    is the audit trail, and an audit trail that a production log level discards
    is not one. It is one line per authorized call, which is real volume and the
    honest cost of being able to answer what an agent did.

    The deciding rule is written to the log and **never** to the raised error.
    ``PolicyDeniedError.details`` is rendered straight into the JSON-RPC ``data``
    the caller sees, so putting the rule there would be an oracle: a caller
    learning which rule denied it, or that the tool exists but is forbidden, can
    map the policy one request at a time. The log gets the rule; the caller gets
    an undifferentiated refusal — the same split ``AuthenticationError`` makes
    between its logged reason and its wire message.
    """
    decision = evaluate(policy, principal, tool, arguments)
    _record(decision, principal, tool, arguments if arguments is not None else {})
    if decision.allowed:
        return decision
    if decision.requires_approval:
        # Not a denial and not a permission. The caller decides what to do with
        # it — the request path starts an approval (ADR 0048); anything else
        # that has not been taught about approvals never reaches this branch,
        # because it asked `decision.allowed` and got False.
        return decision
    raise PolicyDeniedError("this call was not permitted")
