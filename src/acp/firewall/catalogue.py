"""Screening tool descriptions, which are model-visible text (threat model section 6.2).

Screens each tool's description and every nested schema ``description``, with the
tool-mention detector told the catalogue minus the tool itself. A tool crossing
the result bar (`triggers_for`) is withheld in enforce mode and served-and-logged
in report mode; descriptions are never fenced, since they are meant to be followed
(ADR 0037). The schema fingerprint (ADR 0013) only notices changes. Measured on
1,096 third-party descriptions before wiring (ADR 0065).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Any

from acp.firewall.findings import Finding
from acp.firewall.screen import Screening
from acp.upstream.models import ToolDefinition

SCHEMA_DESCRIPTION_KEY = "description"


def schema_descriptions(schema: Any, *, depth: int = 0, limit: int = 32) -> Iterator[str]:
    """Every ``description`` string in a JSON schema, down to ``limit`` levels.

    The bound stops an upstream-supplied deep nest from making the walk expensive.
    """
    if depth > limit:
        return
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key == SCHEMA_DESCRIPTION_KEY and isinstance(value, str):
                yield value
            else:
                yield from schema_descriptions(value, depth=depth + 1, limit=limit)
    elif isinstance(schema, list):
        for item in schema:
            yield from schema_descriptions(item, depth=depth + 1, limit=limit)


def description_texts(tool: ToolDefinition) -> list[str]:
    """The prose a model reads about ``tool``: its description, then its schema's."""
    texts = [tool.description] if tool.description else []
    texts.extend(schema_descriptions(tool.input_schema))
    return texts


def others(tool: ToolDefinition, catalogue: AbstractSet[str]) -> frozenset[str]:
    """The catalogue as the tool-mention detector should see it for ``tool``."""
    return frozenset(catalogue) - {tool.name}


@dataclass(frozen=True, slots=True)
class ToolInspection:
    """One tool's description screened, and what the gateway did about it."""

    tool: ToolDefinition
    screening: Screening
    withheld: bool
    triggers: tuple[Finding, ...] = ()
    incident: str = ""


@dataclass(frozen=True, slots=True)
class CatalogueInspection:
    """A whole catalogue screened: what is served, and what was not."""

    served: list[ToolDefinition]
    inspections: tuple[ToolInspection, ...]

    @property
    def withheld(self) -> tuple[ToolInspection, ...]:
        return tuple(i for i in self.inspections if i.withheld)

    @property
    def flagged(self) -> tuple[ToolInspection, ...]:
        """Every tool with any finding, served or not."""
        return tuple(i for i in self.inspections if i.screening.findings)


def names_of(tools: Iterable[ToolDefinition]) -> frozenset[str]:
    return frozenset(tool.name for tool in tools)


def serve(inspections: Sequence[ToolInspection]) -> list[ToolDefinition]:
    """The tools a caller receives: everything not withheld, in catalogue order."""
    return [i.tool for i in inspections if not i.withheld]
