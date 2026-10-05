"""Enforce a policy decision in the request path, and record it either way.

This is the backstop behind catalogue filtering: a caller can still name a hidden
tool directly. Every decision is logged, allows included, because the audit chain
and the policy simulator need the full record. Called once, from
``server.on_call_tool``.
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

    One shape for every outcome. Names both subject and actor. Records sorted argument
    names, never values: values are user data, while names let the simulator (ADR 0045)
    settle rules on arguments the call never sent (ADR 0031).
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

    Returns:
        The ``Decision`` when allowed or held for approval (ADR 0048); the caller must
        check ``requires_approval``.

    Raises:
        PolicyDeniedError: on an explicit deny or the deny default.

    Every decision is logged at INFO (it is the audit trail) before returning or
    raising. The deciding rule goes to the log only, never the error, which reaches the
    caller and would otherwise let them map the policy.
    """
    decision = evaluate(policy, principal, tool, arguments)
    _record(decision, principal, tool, arguments if arguments is not None else {})
    if decision.allowed:
        return decision
    if decision.requires_approval:
        # Held, not permitted: the request path starts an approval (ADR 0048).
        return decision
    raise PolicyDeniedError("this call was not permitted")
