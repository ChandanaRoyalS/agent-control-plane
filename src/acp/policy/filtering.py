"""Filter a tool catalogue to what a principal is allowed to see.

Hides tools in ``tools/list`` that the caller could never use; ``enforce_call`` still
refuses them if named directly. A listing has no arguments, so visibility asks
`could_ever_allow`, the same question pre-dispatch asks (ADR 0072). Pure; called
from ``server.on_list_tools``.
"""

from __future__ import annotations

from collections.abc import Sequence

from acp.identity.principal import Principal
from acp.policy.evaluate import could_ever_allow
from acp.policy.schema import Policy
from acp.upstream.models import ToolDefinition


def visible_tools(
    policy: Policy, principal: Principal, tools: Sequence[ToolDefinition]
) -> list[ToolDefinition]:
    """Return the tools ``principal`` could call under ``policy``, for some arguments.

    Matches on the qualified name (ADR 0003). Tools behind approval (ADR 0048) or an
    argument-scoped grant stay visible. Order is preserved for prompt caching (see
    ``on_list_tools``).
    """
    return [tool for tool in tools if could_ever_allow(policy, principal, tool.name)]
