"""Qualified tool names: ``<upstream>__<tool>``.

See ADR 0003 and its amendment. Two properties make routing work:

**The upstream segment is never ambiguous.** ``UpstreamConfig`` rejects
underscores in upstream names, so the first ``__`` in a qualified name always
separates upstream from tool — even when the tool half was truncated, and even
when the tool's own name contains ``__``. Routing to the right server is
therefore always exact.

**Truncation is lossy and cannot be reversed.** When a qualified name would
exceed the length limit the tool half is shortened and a hash of the *full*
name is appended. Nothing recovers the original from the result.

What *is* available is a sound one-sided test. Truncation always fills the name
to exactly ``MAX_QUALIFIED_LENGTH`` by construction, so any shorter name is
definitely intact and its suffix is the upstream's real tool name — no state,
no lookup. Only names at exactly the limit are ambiguous (a tool could
legitimately be named that long), and those are resolved through the upstream's
catalogue.

An earlier version of this module tried to detect truncation by re-qualifying
the suffix and comparing. That is always false: a truncated name is itself
under the limit, so re-qualifying it is a no-op and matches every time. A
randomised check over 200,000 name pairs caught it; the mistake is recorded
here because the idea is superficially convincing.
"""

from __future__ import annotations

import hashlib

SEPARATOR = "__"
"""Separator between the upstream and tool halves.

Double underscore rather than ``.``, ``/`` or ``:``, none of which are reliably
legal in tool names across MCP clients (ADR 0003).
"""

MAX_QUALIFIED_LENGTH = 64
"""Conservative ceiling on a qualified tool name.

Several MCP clients cap tool names around here, and the failure mode when one
is exceeded is a client-side validation error far from the cause. Staying under
it is cheaper than diagnosing that.
"""

HASH_LENGTH = 6
"""Hex characters of digest appended to a truncated name.

Six gives ~16.7 million values. Collisions only matter *within one upstream*
between two tools whose names share a long prefix, which makes the practical
risk negligible while keeping names readable.
"""

TRUNCATION_MARKER = "-"


class MalformedToolNameError(ValueError):
    """A qualified name that does not contain the separator at all."""


def qualify(upstream: str, tool: str) -> str:
    """Build the qualified name a client will see for ``tool`` on ``upstream``.

    Deterministic: the same pair always produces the same name, across
    processes and machines. That matters because policy rules and audit records
    reference these names, and a name that changed between restarts would
    silently invalidate both.
    """
    candidate = f"{upstream}{SEPARATOR}{tool}"
    if len(candidate) <= MAX_QUALIFIED_LENGTH:
        return candidate

    # Hash the *full* candidate, not the truncated remainder, so two tools that
    # share a long prefix still differ after truncation.
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
    """Extract the upstream name from a qualified tool name.

    Always exact, including for truncated names — see the module docstring.
    """
    upstream, separator, _ = qualified.partition(SEPARATOR)
    if not separator or not upstream:
        msg = f"tool name {qualified!r} is not qualified with {SEPARATOR!r}"
        raise MalformedToolNameError(msg)
    return upstream


def suffix_of(qualified: str) -> str:
    """Everything after the first separator.

    For an untruncated name this *is* the upstream's tool name. For a truncated
    one it is the shortened form, which cannot be used directly — use
    :func:`is_truncated` to tell them apart.
    """
    _, separator, suffix = qualified.partition(SEPARATOR)
    if not separator:
        msg = f"tool name {qualified!r} is not qualified with {SEPARATOR!r}"
        raise MalformedToolNameError(msg)
    return suffix


def may_be_truncated(qualified: str) -> bool:
    """Whether ``qualified`` *could* be a shortened form, and so needs resolving.

    Deliberately one-sided, and named to say so. ``False`` is certain: truncation
    always fills a name to exactly ``MAX_QUALIFIED_LENGTH``, so anything shorter
    is intact and :func:`suffix_of` gives the upstream's real tool name directly.

    ``True`` is only a maybe — a tool legitimately named to exactly the limit is
    indistinguishable from a truncated one, and no test on the string can tell
    them apart. Callers must resolve those through the upstream's catalogue
    rather than guessing, because guessing wrong means invoking the wrong tool.
    """
    return len(qualified) >= MAX_QUALIFIED_LENGTH
