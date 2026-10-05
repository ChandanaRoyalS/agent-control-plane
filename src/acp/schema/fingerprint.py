"""Fingerprinting tool definitions so any change the model could see changes the digest.

The digest covers the whole definition, description and unknown fields included. Only object
key order is canonicalised; array order is kept, since guessing which arrays are sets could
hide a real change, and reordering also invalidates the provider's prompt cache.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from acp.upstream.models import ToolDefinition

SHORT_DIGEST_CHARS = 12
"""Digest prefix length for display only; comparisons use the full digest."""


def canonical_json(value: Any) -> str:
    """Sorted-key compact JSON, non-ASCII kept so hidden characters still change the digest."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    """SHA-256 hex digest of the canonical form of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def short(value: str | None) -> str | None:
    """Truncate a digest for display, passing ``None`` through untouched."""
    return value if value is None else value[:SHORT_DIGEST_CHARS]


def definition_of(tool: ToolDefinition) -> dict[str, Any]:
    """The tool's wire form (``inputSchema``, not ``input_schema``), as the upstream sent it."""
    dumped: dict[str, Any] = tool.model_dump(by_alias=True, mode="json")
    return dumped


def definitions_of(tools: list[ToolDefinition]) -> dict[str, dict[str, Any]]:
    """Every tool keyed by name, so a rename reads as a removal plus an addition."""
    return {tool.name: definition_of(tool) for tool in tools}


def fingerprint_tool(definition: Mapping[str, Any]) -> str:
    """The digest of one tool definition."""
    return digest(definition)


def fingerprint_catalogue(definitions: Mapping[str, Mapping[str, Any]]) -> str:
    """The digest of a catalogue, computed over its per-tool digests."""
    return digest({name: fingerprint_tool(d) for name, d in definitions.items()})
