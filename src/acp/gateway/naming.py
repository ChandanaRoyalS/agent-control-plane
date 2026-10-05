"""Qualified tool names: ``<upstream>__<tool>`` (ADR 0003 and its amendment).

Upstream names cannot contain underscores, so the first ``__`` always separates upstream
from tool and routing is exact. Over-long names are truncated with a hash of the full
name, which is irreversible. Truncation fills exactly ``MAX_QUALIFIED_LENGTH``, so a
shorter name is intact; names at the limit must be resolved via the catalogue.
"""

from __future__ import annotations

import hashlib

SEPARATOR = "__"
"""Separator between upstream and tool; ``.``, ``/`` and ``:`` are not portable (ADR 0003)."""

MAX_QUALIFIED_LENGTH = 64
"""Conservative ceiling on a qualified tool name, below common MCP client limits."""

HASH_LENGTH = 6
"""Hex digest characters appended to a truncated name (collisions matter only per upstream)."""

TRUNCATION_MARKER = "-"


class MalformedToolNameError(ValueError):
    """A qualified name that does not contain the separator at all."""


def qualify(upstream: str, tool: str) -> str:
    """Build the qualified name a client sees for ``tool`` on ``upstream``.

    Deterministic across processes, since policy rules and audit records use these names.

    Raises:
        ValueError: The upstream name leaves no room for a tool name.
    """
    candidate = f"{upstream}{SEPARATOR}{tool}"
    if len(candidate) <= MAX_QUALIFIED_LENGTH:
        return candidate

    # Hash the full name so tools sharing a long prefix still differ.
    digest = hashlib.sha256(candidate.encode()).hexdigest()[:HASH_LENGTH]
    prefix = f"{upstream}{SEPARATOR}"
    room = MAX_QUALIFIED_LENGTH - len(prefix) - HASH_LENGTH - len(TRUNCATION_MARKER)
    if room < 1:
        msg = (
            f"upstream name {upstream!r} leaves no room for a tool name within "
            f"{MAX_QUALIFIED_LENGTH} characters"
        )
        raise ValueError(msg)
    return f"{prefix}{tool[:room]}{TRUNCATION_MARKER}{digest}"


def upstream_of(qualified: str) -> str:
    """Extract the upstream name; exact even for truncated names.

    Raises:
        MalformedToolNameError: No separator or empty upstream.
    """
    upstream, separator, _ = qualified.partition(SEPARATOR)
    if not separator or not upstream:
        msg = f"tool name {qualified!r} is not qualified with {SEPARATOR!r}"
        raise MalformedToolNameError(msg)
    return upstream


def suffix_of(qualified: str) -> str:
    """Return everything after the first separator.

    This is the real tool name only if the name is not truncated; see
    :func:`may_be_truncated`.
    """
    _, separator, suffix = qualified.partition(SEPARATOR)
    if not separator:
        msg = f"tool name {qualified!r} is not qualified with {SEPARATOR!r}"
        raise MalformedToolNameError(msg)
    return suffix


def may_be_truncated(qualified: str) -> bool:
    """Return whether ``qualified`` could be truncated and so needs resolving.

    ``False`` is certain. ``True`` is only a maybe: resolve it via the upstream's
    catalogue, since guessing could invoke the wrong tool.
    """
    return len(qualified) >= MAX_QUALIFIED_LENGTH
