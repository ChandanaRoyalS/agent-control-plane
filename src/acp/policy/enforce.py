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

from acp.exceptions import PolicyDeniedError
from acp.identity.principal import Principal
from acp.policy.evaluate import evaluate
from acp.policy.schema import Policy


def enforce_call(policy: Policy, principal: Principal, tool: str) -> None:
    """Allow the call to proceed, or raise ``PolicyDeniedError``.

    Returns ``None`` when the policy allows ``principal`` to call ``tool``. On a
    denial — an explicit deny rule, or no rule matching, which is the deny
    default — raises ``PolicyDeniedError`` carrying the deciding rule's name (or
    ``None`` for the default) in ``details`` for the audit log.

    The message is deliberately uninformative about *why*. A caller learning
    that a tool exists but is forbidden, or which rule forbade it, is an oracle;
    the log gets the detail, the caller gets a refusal. This mirrors how
    ``AuthenticationError`` strips its reason before it reaches the wire.
    """
    decision = evaluate(policy, principal, tool)
    if decision.allowed:
        return
    raise PolicyDeniedError(
        f"call to {tool!r} was not permitted",
        details={"rule": decision.rule, "tool": tool},
    )
