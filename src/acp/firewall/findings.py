"""What a detector says when it sees something, and why it says so carefully.

A finding is a *claim about text*, not a verdict about a request. Nothing here
blocks anything: detection and decision are separate tasks (45 and 47) because
combining them makes the false-positive rate impossible to measure — a detector
that also refuses can only be evaluated by counting refusals, and by then the
damage to a legitimate caller has already happened.

Three fields carry the weight.

**Family** is what makes the numbers mean anything. A single detection rate over
a mixed corpus tells you nothing actionable: 80% could be excellent coverage of
every family, or perfect coverage of the easy ones and nothing at all on
encoding attacks. Task 49's corpus is sliced by family precisely so the result
can be read, and a finding that does not name its family cannot be sliced.

**Confidence, not severity.** A deliberate word. Severity asks "how bad would
this be", which is a question about the *tool being called* and belongs to the
policy engine. Confidence asks "how sure am I this is an attack at all", which
is the only question a pattern can answer. Conflating them produces a detector
that reports HIGH because a delete tool exists somewhere, and nobody can tell
whether the pattern actually fired well.

**Evidence is attacker-controlled text on its way to a log line.** It is
excerpted from a document written by whoever is attacking, so it is truncated,
stripped of control characters, and rendered with escapes. A finding that pasted
raw bytes into a log would let an attacker forge log lines, inject terminal
escape sequences into whoever greps them, or simply carry the injection into the
next system that reads the log — which is the same class of mistake as the
original attack, committed by the thing built to detect it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

MAX_EVIDENCE = 80
"""How much of a match to keep. Enough to recognise, too little to carry a
payload — a log line is not a place to reproduce an attack in full."""


class Family(StrEnum):
    """The attack families the corpus is sliced by (task 49).

    Named here rather than in the corpus so that a detector and the examples
    that test it cannot drift into describing different things.
    """

    DIRECT_OVERRIDE = "direct_override"
    """Text telling the model to disregard what it was asked and do something
    else. The obvious family, and the one everybody tests; also the one with the
    worst false-positive problem, because writing *about* prompt injection means
    writing the same sentences."""

    EXFILTRATION = "exfiltration"
    """Getting data out through something the client will render or fetch. A
    markdown image whose URL carries the secret is the canonical case: the model
    never "sends" anything, it just emits text, and the client's renderer makes
    the request."""

    OBFUSCATION = "obfuscation"
    """Hiding the payload from a reader or a matcher — zero-width characters
    inside a word, bidirectional overrides that reverse what a human sees,
    base64 that a model will happily decode and a regex will not."""

    TOOL_CONFUSION = "tool_confusion"
    """Naming tools the reading model has, in text the model was not supposed to
    take instruction from. The gateway is the only component that can detect
    this at all, because it is the only one that knows the whole catalogue."""

    BOUNDARY_ESCAPE = "boundary_escape"
    """Text impersonating the framing around it — fake system turns, fake
    delimiters, fake end-of-document markers. Aimed at whatever wraps the
    content, which from task 46 is this gateway's own provenance envelope."""


class Confidence(StrEnum):
    """How sure the detector is that this is an attack.

    Not how dangerous it would be. See the module docstring.
    """

    LOW = "low"
    """Worth counting, not worth acting on alone. Legitimate documents produce
    these — a security advisory, a prompt-engineering tutorial, this
    repository's own ADRs."""

    MEDIUM = "medium"
    """Unusual in ordinary text and cheap to explain to a human."""

    HIGH = "high"
    """Effectively never appears by accident. A bidirectional override inside a
    tool result is not a formatting choice."""


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def redact(text: str) -> str:
    """An excerpt safe to put in a log line.

    Three things, each closing a way the evidence field could become the attack:
    control characters are replaced, because an ANSI escape in a log line
    rewrites the terminal of whoever reads it; the result is truncated, because
    a log is not a place to reproduce a payload; and newlines go, because a log
    line that can contain a newline is a log line an attacker can forge a second
    entry with.
    """
    collapsed = " ".join(text.split())
    cleaned = _CONTROL.sub("�", collapsed)
    if len(cleaned) <= MAX_EVIDENCE:
        return cleaned
    return cleaned[: MAX_EVIDENCE - 1] + "…"


@dataclass(frozen=True, slots=True)
class Finding:
    """One detector's claim about one span of text."""

    detector: str
    """Which detector fired, so a false positive can be attributed to a rule
    rather than to "the firewall" — the difference between tuning one pattern
    and switching the layer off."""

    family: Family
    confidence: Confidence
    evidence: str
    offset: int = -1
    """Where in the screened text, or ``-1`` when the finding is about the text
    as a whole. Kept because "which paragraph" is the first question anybody
    asks, and recomputing it later means re-running the detector."""

    def __post_init__(self) -> None:
        # Redacting here rather than at every call site: a constructor that
        # cannot be given unsafe evidence is a guarantee, where a convention
        # that every detector must remember to redact is a habit.
        object.__setattr__(self, "evidence", redact(self.evidence))

    @property
    def label(self) -> str:
        return f"{self.detector} ({self.family}, {self.confidence})"


def describe(codepoint: str) -> str:
    """A character's Unicode name, for evidence a human can act on.

    `U+202E` means nothing to most readers; `RIGHT-TO-LEFT OVERRIDE` means
    something to anyone. A finding nobody can interpret gets ignored, and an
    ignored detector is a disabled detector with extra steps.
    """
    try:
        return unicodedata.name(codepoint)
    except ValueError:
        return f"U+{ord(codepoint):04X}"


DETECTOR_NAMES: Final = (
    "instruction_override",
    "invisible_characters",
    "bidirectional_override",
    "external_image",
    "disallowed_url",
    "encoded_payload",
    "tool_name_mention",
)
"""Every detector, named once.

The screener asserts its own registry against this tuple, so a detector added
without being registered — or registered without being named — fails a test
rather than silently never running. The same alarm task 31 put on the `Upstream`
protocol, for the same reason: a security layer's coverage should not be able to
shrink quietly.
"""
