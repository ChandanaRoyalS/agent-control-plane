"""Filter a tool catalogue to what a principal is allowed to see.

Task 34 refused a denied call; this is the other half — a tool the caller may
not use is not shown in ``tools/list`` at all, so a well-behaved agent never
learns it exists and never offers it. The two compose: filtering keeps a denied
tool out of sight, and enforcement (task 34) refuses it if the agent names it
anyway from somewhere else. Filtering is defence by construction; enforcement is
the guarantee that makes hiding safe rather than merely tidy.

Pure, like ``enforce_call``: it decides which tools survive and returns them,
with the one call site in ``server.on_list_tools``. It reuses the same
``evaluate`` the enforcer does, so a tool is visible under exactly the condition
it is callable — the list can never advertise a tool the call would refuse, or
hide one the call would allow.
"""

from __future__ import annotations

from collections.abc import Sequence

from acp.identity.principal import Principal
from acp.policy.evaluate import Verdict, evaluate
from acp.policy.schema import Policy
from acp.upstream.models import ToolDefinition


def visible_tools(
    policy: Policy, principal: Principal, tools: Sequence[ToolDefinition]
) -> list[ToolDefinition]:
    """Return only the tools ``principal`` is allowed to call under ``policy``.

    A tool survives iff ``evaluate`` does not *deny* the principal calling it by
    its qualified name (``<upstream>__<tool>``, ADR 0003) — the same name the
    merged catalogue already carries and the same the enforcer matches, so
    visibility and callability cannot drift apart. Order is preserved: the
    catalogue's ordering is a prompt-cache decision (see ``on_list_tools``), and
    filtering must not disturb it.

    **"Not denied" rather than "allowed", and the difference is approvals.** A
    tool held for human approval (ADR 0048) is one the agent is *supposed* to
    ask for — that is the entire point of the flow. Hiding it would mean the
    agent never names it, never triggers the approval, and the operator is never
    asked; the feature would be unreachable from the only client that could use
    it. So the catalogue shows it, the call starts the approval, and the human
    decides. This is the one place where the old rule "visible iff callable"
    needed restating as "visible iff not forbidden".
    """
    return [
        tool for tool in tools if evaluate(policy, principal, tool.name).verdict is not Verdict.DENY
    ]
