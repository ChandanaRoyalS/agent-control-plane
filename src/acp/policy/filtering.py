"""Filter a tool catalogue to what a principal is allowed to see.

Enforcement (``acp.policy.enforce``) refuses a denied call; this is the other
half — a tool the caller may
not use is not shown in ``tools/list`` at all, so a well-behaved agent never
learns it exists and never offers it. The two compose: filtering keeps a denied
tool out of sight, and enforcement refuses it if the agent names it
anyway from somewhere else. Filtering is defence by construction; enforcement is
the guarantee that makes hiding safe rather than merely tidy.

Pure, like ``enforce_call``: it decides which tools survive and returns them,
with the one call site in ``server.on_list_tools``.

**A listing has no arguments, so the question is "could this ever be called",
not "is this call allowed".** The first version asked the evaluator with an
empty argument mapping and called the answer visibility. That hid a tool whose
only grant was argument-scoped ("alice may read the `public` dataset" made the
read tool vanish), and once ADR 0068 made a restriction catch a call that omits
its argument, it hid every tool with an argument-scoped `deny` in front of a
broad `allow` — the README's own example policy. Calls to those tools still
succeeded; an agent could just never find them. The official MCP client's
first run found it (ADR 0072). Visibility now asks `could_ever_allow`, the
same conservative question the pre-dispatch check asks of the routing headers,
so the catalogue and the fast path cannot disagree either.
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

    A tool survives iff `could_ever_allow` says some call to it, by its
    qualified name (``<upstream>__<tool>``, ADR 0003), could be permitted — the
    same name the merged catalogue already carries and the same the enforcer
    matches. Order is preserved: the catalogue's ordering is a prompt-cache
    decision (see ``on_list_tools``), and filtering must not disturb it.

    **"Could be permitted" includes approvals.** A tool held for human
    approval (ADR 0048) is one the agent is *supposed* to ask for — that is the
    entire point of the flow. Hiding it would mean the agent never names it,
    never triggers the approval, and the operator is never asked.

    **And it includes argument-scoped grants.** Visible is not callable with
    any arguments: a tool readable only for some documents is shown, and the
    call with the wrong document is refused by `enforce_call`, which has the
    arguments. Hiding the tool would refuse the right document too, silently,
    by never letting the agent ask.
    """
    return [tool for tool in tools if could_ever_allow(policy, principal, tool.name)]
