"""Which tools may have their results cached, and for how long.

Opt-in in the deployment's file, never inferred: a tool's name is not a contract,
and an upstream must not declare its own results cacheable (ADR 0013). Absent means
off, so an empty table changes nothing (as ADR 0033 did for costs).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

MAX_TTL_SECONDS: Final = 300.0
"""Ceiling on any result's lifetime, whatever the file asks for.

A security limit: policy runs before the cache, but upstream data-level entitlement
changes are invisible here, and the TTL bounds that exposure.
"""


@dataclass(frozen=True)
class CacheableTools:
    """The tools whose results may be cached, each with its own lifetime.

    ``ttls`` maps a qualified tool name (ADR 0003) to seconds; absent means not cacheable.
    """

    ttls: dict[str, float] = field(default_factory=dict)

    def ttl_for(self, tool: str) -> float | None:
        """Return ``tool``'s ttl, or ``None`` if not cacheable (distinct from a configured 0)."""
        return self.ttls.get(tool)

    @property
    def names(self) -> tuple[str, ...]:
        """Every cacheable tool, sorted, for the startup log line."""
        return tuple(sorted(self.ttls))
