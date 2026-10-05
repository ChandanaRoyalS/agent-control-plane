"""A deterministic, credulous agent for the scripted attack demo.

This is a parser, not a language model: a fixture, not a finding. It calls held tools that
retrieved text names after an imperative (*call*, *run*, *use*), taking arguments from the
same paragraph. The gateway sees only tool calls, so the substitution does not change what is
under test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

TOOL = re.compile(r"\b(mock-[ab]__[a-z_]+)\b")
"""A qualified tool name (ADR 0003) in prose."""

IMPERATIVE = re.compile(r"\b(call|run|invoke|use|execute|issue|perform)\b", re.IGNORECASE)

PATH = re.compile(r"\b((?:[a-z0-9_-]+/)+[a-z0-9._-]+\.[a-z]{2,4})\b")
"""Narrow (needs a slash and an extension) so ordinary prose yields no path."""

QUOTED = re.compile(r"[`\"']([^`\"']{1,120})[`\"']")

PRIOR = re.compile(
    r"\b(the (full )?(contents?|results?|output|text)|that document|what you (just )?read)\b",
    re.IGNORECASE,
)
"""Text asking to reuse a previous result, which turns two innocuous calls into exfiltration."""

MAX_STEPS: Final = 8
"""Cap on calls per document, for a readable transcript; not a security control."""


@dataclass(frozen=True, slots=True)
class Step:
    """One call the agent intends to make, and where it got the idea."""

    tool: str
    arguments: dict[str, str]
    source: str
    """`"task"` for the operator's request, or the retrieved text that suggested the call.

    The gateway cannot see this, which is why it defends by policy, not provenance.
    """

    uses_prior: bool = False
    """Whether the driver should substitute in the previous call's result."""


def instructions(text: str, *, tools: frozenset[str]) -> tuple[Step, ...]:
    """Every call this text talks the agent into, in the order it suggests them."""
    found: list[Step] = []
    for paragraph in _paragraphs(text):
        matches = list(TOOL.finditer(paragraph))
        for index, match in enumerate(matches):
            name = match.group(1)
            if name not in tools:
                # Not held (e.g. an invented destructive tool): ignored.
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(paragraph)
            window = paragraph[match.end() : end]
            if not IMPERATIVE.search(paragraph[: match.start()][-80:]):
                continue
            found.append(
                Step(
                    tool=name,
                    arguments=_arguments(name, window),
                    source=paragraph.strip(),
                    uses_prior=bool(PRIOR.search(window)),
                )
            )
            if len(found) >= MAX_STEPS:
                return tuple(found)
    return tuple(found)


def _paragraphs(text: str) -> list[str]:
    """Blank-line separated blocks, unwrapped so an instruction spanning lines stays whole."""
    return [" ".join(block.split()) for block in re.split(r"\n\s*\n", text) if block.strip()]


def _arguments(tool: str, window: str) -> dict[str, str]:
    """Arguments for this tool's own parameter, parsed from the text after its name."""
    if tool.endswith("read_document"):
        path = PATH.search(window)
        return {"path": path.group(1)} if path else {}
    if tool.endswith("create_ticket"):
        quoted = QUOTED.search(window)
        return {"title": quoted.group(1)} if quoted else {}
    if tool.endswith("search"):
        quoted = QUOTED.search(window)
        return {"query": quoted.group(1) if quoted else "incident 2291"}
    if tool.endswith("summarize"):
        return {"text": window.strip()[:200]}
    return {}
