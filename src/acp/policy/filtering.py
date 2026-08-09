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
from acp.policy.evaluate import evaluate
from acp.policy.schema import Policy
from acp.upstream.models import ToolDefinition


def visible_tools(
    policy: Policy, principal: Principal, tools: Sequence[ToolDefinition]
) -> list[ToolDefinition]:
    """Return only the tools ``principal`` is allowed to call under ``policy``.

    A tool survives iff ``evaluate`` allows the principal to call it by its
    qualified name (``<upstream>__<tool>``, ADR 0003) — the same name the merged
    catalogue already carries and the same the enforcer matches, so visibility
    and callability cannot drift apart. Order is preserved: the catalogue's
    ordering is a prompt-cache decision (see ``on_list_tools``), and filtering
    must not disturb it.
    """
    return [tool for tool in tools if evaluate(policy, principal, tool.name).allowed]
