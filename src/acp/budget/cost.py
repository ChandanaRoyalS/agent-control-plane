"""Per-tool call costs, so expensive tools draw more budget than cheap ones.

Unlisted tools cost the default (1.0), so no cost table means every call costs one.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CostTable:
    """What each tool costs, with a default for tools not named.

    ``costs`` maps a qualified tool name (ADR 0003) to its cost in tokens. Costs are
    non-negative; zero is a legitimate free call.
    """

    costs: dict[str, float] = field(default_factory=dict)
    default: float = 1.0

    def cost_of(self, tool: str) -> float:
        """Return ``tool``'s listed cost, or the default."""
        return self.costs.get(tool, self.default)
