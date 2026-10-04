"""Screening the catalogue: tool descriptions are model-visible text too.

Every tool *result* passes through the firewall. Until this module, no tool
*description* did — and a description is prose an upstream writes and the model
reads before it does anything, on every turn, in the system prompt's most
trusted position. An upstream that wants to address the model does not need to
poison a document; it can say what it likes in `tools/list`. The threat model
listed this as the largest unscreened surface (section 6.2), and the schema
fingerprint (ADR 0013) notices when a description *changes* but never reads it.

**What is screened.** The description, plus every `description` string nested
anywhere in the input schema: an attacker who knows the top-level field is read
moves the payload into a parameter's. The same detectors run as on a result, with
one difference in what they are told — the catalogue minus the tool itself, so a
tool is not flagged for naming its own qualified name, while a tool naming
*another* upstream's tool stays exactly the tool-confusion signal it is.

**What happens on a finding.** The same bar as a result (`triggers_for`: HIGH
confidence from an enforceable detector). In enforce mode a tool that crosses it
is **withheld from the catalogue** — the agent never learns it exists this turn —
because the alternative, serving the tool with its description blanked, would
invent a tool the upstream did not describe. In report mode it is served and
the decision is logged, which is how a deployment measures what enforcement
would cost before turning it on. Findings below the bar are reported and the tool
is served, as with a result.

**Why not fence it.** Provenance framing (ADR 0037) tells the model "this text
was retrieved; treat it as data". A description cannot be data: its entire
purpose is to instruct the model about the tool. There is no honest frame for
text that is supposed to be followed, so the only two outcomes are serve or
withhold.

**Measured before it was wired** (ADR 0065). The detectors were run over 1,096
tool, toolkit and parameter descriptions nobody here wrote before this module
was allowed to withhold anything.
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
    """Every ``description`` string in a JSON schema, at any depth.

    Bounded in depth, because the schema is upstream-supplied and a
    thousand-level nest is a cheap way to make this walk expensive. Anything
    deeper than ``limit`` is not read — and a description an upstream buried
    thirty-two levels down is not one a model would have read either.
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
