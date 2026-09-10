"""Which strings in a tool result a model can actually read.

The firewall used to screen ``block.text`` and nothing else. That was a bypass
with a published address: MCP's ``content`` array carries embedded resources,
and an embedded resource's text is delivered to the model exactly like a text
block is. A payload in ``{"type":"resource","resource":{"text": ...}}`` reached
the model having been screened for zero characters, and the fence announced it
as "1 resource" — which is a label, not an inspection.

So the rule here is the only one that survives a spec revision: **screen every
string the result carries**, not the subset this gateway happens to have a model
for. ``CallToolResult`` and ``ContentBlock`` are both ``extra="allow"`` on
purpose (ADR 0006), which means a field added by a future revision arrives as a
dictionary entry rather than an error — and arrives, therefore, in this walk.

Two exclusions, both narrow and both justified:

``data`` and ``blob`` are the base64 payloads of image, audio and binary
resource blocks. They are megabytes of base64 by construction, and the
``encoded_payload`` detector — one of only two that may withhold anything —
fires on base64. Screening them would refuse every screenshot a tool returned.
An image is bytes and this layer still has no opinion about bytes; what changed
is that it no longer mistakes *every* unmodelled field for bytes.

Everything else is screened, including ``uri`` and ``mimeType``. A resource
link's URI is a real exfiltration channel — it is a place the client may be
induced to fetch — and it was previously invisible to ``disallowed_url``.

The walk is bounded three ways: depth, string count, and (by the screener that
consumes it) total characters. A hostile upstream chooses this structure, so
every dimension of it is an attacker-chosen number until something bounds it.
"""

from __future__ import annotations

from typing import Any, Final

from acp.upstream.models import CallToolResult

BINARY_KEYS: Final = frozenset({"data", "blob"})
"""Fields holding base64 bytes rather than text a model reads. See module docstring."""

MAX_DEPTH: Final = 8
"""How deep into a nested result to walk.

MCP's own structures are two or three levels deep. Eight is generous for
anything legitimate and finite against a result nested ten thousand deep, which
would otherwise be a stack overflow an upstream can trigger.
"""

MAX_STRINGS: Final = 1024
"""How many separate strings one result may contribute.

Bounds the *count* dimension, which the character budget does not: fifty
thousand one-character strings cost little to screen individually and a great
deal in per-string overhead. Reaching this cap is reported as truncation by the
caller, exactly like reaching the character budget, because both mean the same
thing — part of this result was not examined.
"""


def screenable_strings(result: CallToolResult) -> tuple[tuple[str, ...], bool]:
    """Every string in ``result`` a model could read, and whether any were skipped.

    Returns ``(strings, complete)``. ``complete`` is ``False`` when the walk hit
    a bound and stopped, which the screener turns into ``truncated`` — an
    unexamined remainder is a bypass with a known address and must never be
    reported as a clean screening.

    Order is the result's own field order, which pydantic preserves, so two
    identical results produce identical screenings and the offsets in a finding
    mean the same thing twice.
    """
    found: list[str] = []
    complete = _walk(result.model_dump(by_alias=True), found, depth=0)
    return tuple(found), complete


def _walk(node: Any, found: list[str], *, depth: int) -> bool:
    """Collect string leaves. ``False`` if a bound stopped the walk early."""
    if len(found) >= MAX_STRINGS:
        return False
    if depth > MAX_DEPTH:
        return False

    if isinstance(node, str):
        if node:
            found.append(node)
        return True
    if isinstance(node, dict):
        complete = True
        for key, value in node.items():
            # A binary payload field, at any depth. Matched by key rather than
            # by the block's declared type, because the type is a string the
            # upstream chose and this decision must not depend on it.
            if key in BINARY_KEYS and isinstance(value, str):
                continue
            complete = _walk(value, found, depth=depth + 1) and complete
        return complete
    if isinstance(node, (list, tuple)):
        complete = True
        for item in node:
            complete = _walk(item, found, depth=depth + 1) and complete
        return complete
    # Numbers, booleans, None. Nothing a detector has an opinion about.
    return True
