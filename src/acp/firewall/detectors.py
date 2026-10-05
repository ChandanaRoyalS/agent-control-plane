"""Pattern detectors: free, deterministic, explainable checks run before any model.

Each states what trips it legitimately; detectors that fire on honest text report
LOW or MEDIUM. Screened text is hostile, so every pattern is linear (no
backtracking traps) and runs on input the screener has already bounded.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from collections.abc import Set as AbstractSet
from typing import Final
from urllib.parse import urlsplit

from acp.firewall.findings import Confidence, Family, Finding, describe

# ---------------------------------------------------------------------------
# Instruction-shaped language
# ---------------------------------------------------------------------------

_OVERRIDE_PATTERNS: Final[tuple[tuple[str, Confidence], ...]] = (
    (
        r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+instructions?",
        Confidence.LOW,
    ),
    (r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+\w+", Confidence.LOW),
    (r"forget\s+(?:everything|all)\s+(?:you|above|before)", Confidence.LOW),
    (r"you\s+are\s+now\s+(?:a|an|the)\s+\w+", Confidence.LOW),
    (r"new\s+(?:system\s+)?instructions?\s*:", Confidence.MEDIUM),
    (r"</?(?:system|assistant|user)>", Confidence.MEDIUM),
    (r"\bBEGIN\s+SYSTEM\s+PROMPT\b", Confidence.MEDIUM),
    (
        r"do\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+(?:user|human|operator)",
        Confidence.MEDIUM,
    ),
)

_OVERRIDE: Final = tuple(
    (re.compile(pattern, re.IGNORECASE), confidence) for pattern, confidence in _OVERRIDE_PATTERNS
)


def instruction_override(text: str) -> Iterator[Finding]:
    """Text that reads as an instruction to abandon the current one.

    Inherently the noisiest detector (prose about injection quotes the phrases),
    so most patterns are LOW; MEDIUM is kept for shapes absent from such prose,
    like a literal `<system>` tag or an instruction to conceal from the user.
    """
    for pattern, confidence in _OVERRIDE:
        for match in pattern.finditer(text):
            yield Finding(
                detector="instruction_override",
                family=Family.DIRECT_OVERRIDE,
                confidence=confidence,
                evidence=match.group(0),
                offset=match.start(),
            )


# ---------------------------------------------------------------------------
# Characters that are not meant to be seen
# ---------------------------------------------------------------------------

INVISIBLE: Final = frozenset("\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e")
"""Zero-width and soft-hyphen characters, which hide text from humans and break regexes.

`\\ufeff` is included; the reported offset tells a leading BOM from a buried one.
"""

BIDI_OVERRIDES: Final = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
"""Bidirectional overrides and isolates (Trojan Source); HIGH confidence.

Directional marks (`\\u200e`, `\\u200f`) used by Arabic and Hebrew are excluded.
"""


def invisible_characters(text: str) -> Iterator[Finding]:
    """Zero-width characters, which hide from a human and from a regex alike."""
    for index, character in enumerate(text):
        if character in INVISIBLE:
            yield Finding(
                detector="invisible_characters",
                family=Family.OBFUSCATION,
                confidence=Confidence.MEDIUM,
                evidence=describe(character),
                offset=index,
            )


def bidirectional_override(text: str) -> Iterator[Finding]:
    """Directional overrides, which make the rendering lie about the bytes."""
    for index, character in enumerate(text):
        if character in BIDI_OVERRIDES:
            yield Finding(
                detector="bidirectional_override",
                family=Family.OBFUSCATION,
                confidence=Confidence.HIGH,
                evidence=describe(character),
                offset=index,
            )


def strip_invisible(text: str) -> str:
    """Remove invisible and bidi characters, after the screener has recorded them.

    Order matters: detect, then strip, then run the other detectors on clean text.
    """
    return "".join(c for c in text if c not in INVISIBLE and c not in BIDI_OVERRIDES)


# ---------------------------------------------------------------------------
# Getting data out
# ---------------------------------------------------------------------------

_IMAGE: Final = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*([^)\s]{1,2000})", re.IGNORECASE)
_URL: Final = re.compile(r"\bhttps?://[^\s<>\"'\])]{1,2000}", re.IGNORECASE)


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def external_image(text: str, allowed_hosts: AbstractSet[str] = frozenset()) -> Iterator[Finding]:
    """A markdown image on a non-allowed host: HIGH, since clients fetch images unclicked."""
    for match in _IMAGE.finditer(text):
        url = match.group(1)
        host = _host_of(url)
        if host and host not in allowed_hosts:
            yield Finding(
                detector="external_image",
                family=Family.EXFILTRATION,
                confidence=Confidence.HIGH,
                evidence=url,
                offset=match.start(),
            )


def disallowed_url(text: str, allowed_hosts: AbstractSet[str] = frozenset()) -> Iterator[Finding]:
    """Any URL whose host is not on the allow-list; MEDIUM, since honest documents link out."""
    for match in _URL.finditer(text):
        host = _host_of(match.group(0))
        if host and host not in allowed_hosts:
            yield Finding(
                detector="disallowed_url",
                family=Family.EXFILTRATION,
                confidence=Confidence.MEDIUM,
                evidence=match.group(0),
                offset=match.start(),
            )


# ---------------------------------------------------------------------------
# Encoded payloads
# ---------------------------------------------------------------------------

_BASE64_RUN: Final = re.compile(r"[A-Za-z0-9+/]{24,4000}={0,2}")
"""Base64 runs of at least 24 characters; the only length floor."""


def encoded_payload(text: str) -> Iterator[Finding]:
    """Base64 that decodes to UTF-8 matching an override pattern; HIGH.

    Non-text decodes (images, hashes) are ignored, since long base64 is common.
    """
    for match in _BASE64_RUN.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Binary (an image, digest or key).
            continue
        if not any(pattern.search(decoded) for pattern, _ in _OVERRIDE):
            continue
        yield Finding(
            detector="encoded_payload",
            family=Family.OBFUSCATION,
            confidence=Confidence.HIGH,
            evidence=decoded,
            offset=match.start(),
        )


# ---------------------------------------------------------------------------
# Tools the document should not know about
# ---------------------------------------------------------------------------


def tool_name_mention(text: str, tools: AbstractSet[str] = frozenset()) -> Iterator[Finding]:
    """A tool result naming a qualified tool (ADR 0003) from this gateway's catalogue.

    Only a gateway sees the whole catalogue to detect this. Records of tool calls
    trip it legitimately, so it is not enforceable (ADR 0039).
    """
    for tool in tools:
        start = text.find(tool)
        if start >= 0:
            yield Finding(
                detector="tool_name_mention",
                family=Family.TOOL_CONFUSION,
                confidence=Confidence.HIGH,
                evidence=tool,
                offset=start,
            )
