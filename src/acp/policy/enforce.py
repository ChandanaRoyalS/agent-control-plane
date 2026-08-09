"""Enforce a policy decision in the request path: allow silently, or raise.

Task 33's ``evaluate`` decides; this turns a denial into a refused call. It is
the backstop the whole model rests on — even once task 35 filters denied tools
out of the catalogue so they are never offered, a caller can still name a tool
directly, and this is what stops the call from executing. Filtering is defence
by construction; enforcement is the guarantee behind it.

Kept as a pure function with the request path calling it in exactly one place,
the same shape as the subject-token invariant (task 27): the decision logic is
here and testable, and ``server.on_call_tool`` holds only the one-line call.
"""

from __future__ import annotations

import logging

from acp.exceptions import PolicyDeniedError
from acp.identity.principal import Principal
from acp.policy.evaluate import evaluate
from acp.policy.schema import Policy

logger = logging.getLogger(__name__)


def enforce_call(policy: Policy, principal: Principal, tool: str) -> None:
    """Allow the call to proceed, or raise ``PolicyDeniedError``.

    Returns ``None`` when the policy allows ``principal`` to call ``tool``. On a
    denial — an explicit deny rule, or no rule matching, which is the deny
    default — raises ``PolicyDeniedError``.

    The deciding rule is written to the log and **never** to the raised error.
    ``PolicyDeniedError.details`` is rendered straight into the JSON-RPC ``data``
    the caller sees, so putting the rule there would be an oracle: a caller
    learning which rule denied it, or that the tool exists but is forbidden, can
    map the policy one request at a time. The log gets the rule; the caller gets
    an undifferentiated refusal — the same split ``AuthenticationError`` makes
    between its logged reason and its wire message.
    """
    decision = evaluate(policy, principal, tool)
    if decision.allowed:
        return
    logger.info(
        "policy.denied",
        extra={
            "subject": principal.subject,
            "tool": tool,
            "rule": decision.rule,
        },
    )
    raise PolicyDeniedError("this call was not permitted")
