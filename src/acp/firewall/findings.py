"""Findings: a detector's claim about text, never a verdict (ADR 0036).

Keeping detection apart from decision keeps the false-positive rate measurable.
Each finding names its family (so results can be sliced), a confidence (how sure,
not how severe; severity belongs to policy) and evidence, which is
attacker-controlled and so redacted before it can reach a log.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

MAX_EVIDENCE = 80
"""Max evidence characters: enough to recognise, too few to carry a payload."""


class Family(StrEnum):
    """The attack families the corpus is sliced by, defined once for detectors and corpus."""

    DIRECT_OVERRIDE = "direct_override"
    """Text telling the model to abandon its instructions; the noisiest family."""

    EXFILTRATION = "exfiltration"
    """Data out via something the client renders or fetches, e.g. a markdown image URL."""

    OBFUSCATION = "obfuscation"
    """Hiding a payload: zero-width characters, bidi overrides, base64."""

    TOOL_CONFUSION = "tool_confusion"
    """Untrusted text naming the model's tools; only the gateway sees the catalogue."""

    BOUNDARY_ESCAPE = "boundary_escape"
    """Text impersonating its framing (fake system turns, delimiters, end markers)."""

    PLAIN_ASSERTION = "plain_assertion"
    """A plain request or false claim with no pattern shape; only the classifier reports it.

    See ADR 0040 and ADR 0062.
    """


class Confidence(StrEnum):
    """How sure the detector is that this is an attack (not how dangerous)."""

    LOW = "low"
    """Worth counting, not acting on alone; legitimate documents produce these."""

    MEDIUM = "medium"
    """Unusual in ordinary text and cheap to explain to a human."""

    HIGH = "high"
    """Effectively never appears by accident."""


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def redact(text: str) -> str:
    """A log-safe excerpt: whitespace collapsed (no forged lines), controls replaced, truncated."""
    collapsed = " ".join(text.split())
    cleaned = _CONTROL.sub("�", collapsed)
    if len(cleaned) <= MAX_EVIDENCE:
        return cleaned
    return cleaned[: MAX_EVIDENCE - 1] + "…"


@dataclass(frozen=True, slots=True)
class Finding:
    """One detector's claim about one span of text."""

    detector: str
    """Which detector fired, so a false positive is attributable to one rule."""

    family: Family
    confidence: Confidence
    evidence: str
    offset: int = -1
    """Offset in the screened text, or ``-1`` for the text as a whole."""

    def __post_init__(self) -> None:
        # Redact in the constructor so no call site can forget.
        object.__setattr__(self, "evidence", redact(self.evidence))

    @property
    def label(self) -> str:
        return f"{self.detector} ({self.family}, {self.confidence})"


def describe(codepoint: str) -> str:
    """A character's Unicode name (or ``U+XXXX``), for readable evidence."""
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
"""Every detector, named once; a test checks the screener's registry against it."""
