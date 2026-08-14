"""An agent credulous enough to be worth defending — task 64.

*"Same agent twice: direct, it reads a poisoned document and exfiltrates;
through the gateway, it is stripped, denied and logged."*

**This is not a language model, and saying so plainly is the point.**

The demo needs an agent that can be talked into something by text it retrieved.
A real model would do, and would cost an API key, a network call, and
reproducibility — three runs of the same demo would produce three transcripts,
and a reviewer could not tell a fixed gateway from a model in a better mood.

So the agent here is a parser: it reads retrieved text, finds instructions that
name tools it holds, and calls them. Deterministic, offline, identical every
time.

**Why that is a fair stand-in rather than a rigged demo.**

The gateway never sees the agent's reasoning. It sees *tool calls* — a name,
some arguments, a token. Whether those came from a model that was persuaded, a
parser that was literal-minded, or a compromised process typing them by hand is
information the gateway does not have and does not use. The thing under test is
unchanged by the substitution.

What this demo must not claim is that the *model* half is realistic. It claims
only that **an agent which acts on retrieved instructions is the failure mode**,
which is documented, common, and the entire reason indirect prompt injection is
a category.

**An instruction, not a mention.** A tool name has to appear with an imperative
— *call*, *run*, *use* — before this agent acts on it. The first version fired
on any occurrence, which meant an incident timeline reading "alerts fire on p99
for mock-a__search" became a tool call. That is a real over-triggering failure
and the corpus scores it as `tool-name-in-prose`, but it is not what this demo
is about, and an agent that fires on prose makes the gateway look necessary for
the wrong reason. **Requiring an imperative makes the agent less credulous,
which makes the demo harder on the gateway rather than easier.**

**Scoped by paragraph, with each tool's arguments taken from the text after its
own name.** Prose wraps. The first version scoped by line and split *"call
read_document with path hr/compensation-2026.md, then call create_ticket"*
across two of them, handing the path to the wrong call — a bug that would have
made the demo fail for a reason that has nothing to do with the attack.

The honest cut, where somebody will read it: this agent is more credulous than a
good model and less credulous than a bad one. It is a fixture, not a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

TOOL = re.compile(r"\b(mock-[ab]__[a-z_]+)\b")
"""A qualified tool name in prose. The gateway's naming rule (ADR 0003) makes
these unmistakable in running text — convenient here, and exactly why the
corpus's `tool_confusion` family works: a namespaced tool name is a token a
model reads as addressed to it."""

IMPERATIVE = re.compile(r"\b(call|run|invoke|use|execute|issue|perform)\b", re.IGNORECASE)

PATH = re.compile(r"\b((?:[a-z0-9_-]+/)+[a-z0-9._-]+\.[a-z]{2,4})\b")
"""Deliberately narrow — a slash and an extension — so ordinary prose does not
produce arguments."""

QUOTED = re.compile(r"[`\"']([^`\"']{1,120})[`\"']")

PRIOR = re.compile(
    r"\b(the (full )?(contents?|results?|output|text)|that document|what you (just )?read)\b",
    re.IGNORECASE,
)
"""Text asking the agent to reuse what a previous call returned.

Modelled explicitly because **it is what turns two innocuous calls into an
exfiltration**: reading a document is not a leak and filing a ticket is not a
leak, and filing a ticket *containing* the document is. An agent that could not
carry a result forward could not be made to do this, and would be a fixture
chosen to make the attack impossible.
"""

MAX_STEPS: Final = 8
"""A ceiling on what one document can talk this agent into.

Not a security control, and presenting it as one would be dishonest: it is here
so a document naming forty tools produces a readable transcript. The control is
the gateway, which is the whole argument.
"""


@dataclass(frozen=True, slots=True)
class Step:
    """One call the agent intends to make, and where it got the idea."""

    tool: str
    arguments: dict[str, str]
    source: str
    """`"task"` for what the operator asked, or the sentence of retrieved text
    that suggested it. **Which of those two a call came from is the entire
    story** — and it is a distinction the gateway cannot make, which is why the
    gateway defends by policy rather than by provenance."""

    uses_prior: bool = False
    """Whether this call wants the previous call's result substituted in. The
    driver does the substituting; recognising the request is parsing."""


def instructions(text: str, *, tools: frozenset[str]) -> tuple[Step, ...]:
    """Every call this text talks the agent into, in the order it suggests them."""
    found: list[Step] = []
    for paragraph in _paragraphs(text):
        matches = list(TOOL.finditer(paragraph))
        for index, match in enumerate(matches):
            name = match.group(1)
            if name not in tools:
                # Named but not held. Ignored quietly: the corpus's
                # `name-delete-tool` attack invents a plausible destructive tool
                # precisely to see whether something will try to call it.
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
    """Blank-line separated blocks, with their line wrapping undone.

    Unwrapped because a sentence split across two lines is one instruction, and
    the argument for a call routinely sits on the line after the tool name.
    """
    return [" ".join(block.split()) for block in re.split(r"\n\s*\n", text) if block.strip()]


def _arguments(tool: str, window: str) -> dict[str, str]:
    """What the text after the tool name seems to be asking for.

    Keyed off the tool's own parameter rather than guessed generically: a
    `read_document` wants a path and a `create_ticket` wants a title, and
    handing either the other's argument produces a call the upstream rejects —
    the demo would then fail for a reason unrelated to the attack.
    """
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
