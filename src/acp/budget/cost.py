"""Per-tool call costs: weight a call's budget draw by which tool it is.

Rate limiting (task 38) charges every call one token. But calls are not equal —
a large search or a write is more expensive to serve than a cheap lookup, and a
budget that cannot tell them apart either throttles the cheap ones too hard or
lets the expensive ones through too easily. A cost table maps a qualified tool
name to what it costs; the limiter debits that many tokens instead of one.

Pure and tiny: a mapping plus a default. Unlisted tools cost the default (1.0),
so a gateway with rate limiting on but no cost table behaves exactly as before —
every call costs one, as task 38 left it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CostTable:
    """What each tool costs, with a default for tools not named.

    ``costs`` maps a qualified tool name (``upstream__tool``, ADR 0003) to its
    cost in tokens; ``default`` is charged for any tool not in the map. Costs are
    non-negative — a cost of zero is a free call that draws no budget, which is a
    legitimate choice for a cheap metadata tool, not an error.
    """

    costs: dict[str, float] = field(default_factory=dict)
    default: float = 1.0

    def cost_of(self, tool: str) -> float:
        """The cost of calling ``tool`` — its listed cost, or the default."""
        return self.costs.get(tool, self.default)
