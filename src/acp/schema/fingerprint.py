"""Reducing a tool definition to one value that changes when the tool does.

Everything in this module exists to answer a single question reliably: *is this
the same tool it was last time?* That sounds trivial and is not, because the
answer depends entirely on what you decide counts as "the same", and every
plausible shortcut here hides a real change.

**Hash everything the model can see.** A tool definition is not just its
``inputSchema``. Its ``description`` is a paragraph of natural language that goes
straight into the agent's prompt, and ``ToolDefinition`` allows extra fields, so
a title, an ``outputSchema`` or an ``annotations`` block an upstream adds later
also reaches the model. Anything an upstream can put in front of a model and this
detector does not hash is a blind spot in a security control — so the digest
covers the whole definition, unknown fields included.

**Canonicalise key order, and nothing else.** JSON object key order carries no
meaning, so it is sorted. Array order is left exactly as it arrived, and that is
a deliberate refusal rather than an oversight. It is tempting to sort ``required``
and ``enum`` on the grounds that both are semantically sets — but deciding which
arrays in a JSON Schema are sets requires understanding each keyword, and a
normaliser that guesses wrong does not produce noise, it produces silence about a
real change.

There is a second, harder argument for byte-level fidelity. The model provider's
prompt cache does not normalise either: it hashes the serialised prompt, and the
tool catalogue is *in* that prompt. An upstream that reorders its ``required``
array between calls is invalidating the prompt cache and being billed for the
whole prompt again, whether or not the meaning changed. That is worth an alert on
its own terms, which makes the conservative digest the correct one twice over.

**No exclusions, especially not ``description``.** The description is the field
an attacker would change. A tool that has always been called ``search`` and whose
schema still takes a query, but whose description has quietly grown a sentence
beginning "Before using any other tool…", is the MCP rug pull, and it is
invisible to anything that fingerprints only the schema.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from acp.upstream.models import ToolDefinition

SHORT_DIGEST_CHARS = 12
"""How much of a digest to show a human.

Twelve hex characters is forty-eight bits — far more than enough to tell two
catalogue versions apart by eye, and short enough to sit in a log line without
wrapping. The full digest is what gets compared; this is only ever for display.
"""


def canonical_json(value: Any) -> str:
    """Serialise ``value`` so that equal values always produce equal text.

    Sorted keys, no incidental whitespace, and non-ASCII characters left as
    themselves. That last choice matters: a zero-width joiner or a
    right-to-left override smuggled into a description is part of the string
    and must be part of the digest. Detecting such characters *as* an attack is
    task 45's job — this layer only has to be unable to miss them.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    """A stable SHA-256 over the canonical form of ``value``.

    SHA-256 rather than something faster because the input is tiny and the
    output is compared against a value committed to a repository, where a
    collision would be an attacker's dream and a truncated non-cryptographic
    hash would be their opportunity.
    """
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def short(value: str | None) -> str | None:
    """Truncate a digest for display, passing ``None`` through untouched."""
    return value if value is None else value[:SHORT_DIGEST_CHARS]


def definition_of(tool: ToolDefinition) -> dict[str, Any]:
    """The wire form of one tool, as the upstream sent it.

    ``by_alias`` so the recorded shape is ``inputSchema`` rather than the
    Python-side ``input_schema``. The snapshot file is read by humans comparing
    it against a server's actual response, and a baseline written in field names
    that appear nowhere on the wire is a baseline nobody can check.
    """
    dumped: dict[str, Any] = tool.model_dump(by_alias=True, mode="json")
    return dumped


def definitions_of(tools: list[ToolDefinition]) -> dict[str, dict[str, Any]]:
    """Every tool in a catalogue, keyed by name.

    Keying by name is what makes a rename read as one tool removed and another
    added, which is exactly right: nothing about the gateway can tell a rename
    from a substitution, and treating them as the same event would mean assuming
    good faith about the one case where it is least warranted.
    """
    return {tool.name: definition_of(tool) for tool in tools}


def fingerprint_tool(definition: Mapping[str, Any]) -> str:
    """The digest of one tool definition."""
    return digest(definition)


def fingerprint_catalogue(definitions: Mapping[str, Mapping[str, Any]]) -> str:
    """The digest of a whole catalogue.

    Computed over the per-tool digests rather than the raw definitions, so that
    the catalogue digest changes if and only if some tool's digest does. It also
    makes the derivation auditable: given the file, a reader can recompute each
    tool's digest and then this one, and see where a mismatch came from.
    """
    return digest({name: fingerprint_tool(d) for name, d in definitions.items()})
