"""The pattern layer: what can be caught without a model, and honestly.

Built before reaching for a classifier, because these are free, fast,
deterministic and explainable — and because a detector you cannot explain is one
that gets switched off the first time it is wrong about something important.

**The false-positive rate is the product.** Anyone can catch every attack by
flagging everything; the only interesting question is what a detector does to
the ordinary documents an agent reads all day. So each detector below states
what makes it fire *and* what legitimately trips it, and the ones that cannot
avoid firing on honest text report LOW confidence rather than pretending.

The clearest example is `instruction_override`. A security advisory about prompt
injection, a prompt-engineering tutorial, and this repository's own ADRs all
contain the sentence "ignore previous instructions". They are not attacks. A
detector that reported HIGH on them would be wrong about the most-read documents
in any engineering organisation, and would be turned off within a week.

**The text being screened is hostile input to this code.** It comes from an
upstream that may be compromised — that is the entire premise of Phase 5. So
every pattern here is linear: no nested quantifiers, no backtracking traps, and
the screener bounds the input before any of them run. A detector that can be
made quadratic by a hostile document is a denial-of-service written into the
component built to prevent one.
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

    **The highest false-positive rate here by a wide margin, and it is inherent
    rather than fixable.** Writing about prompt injection means writing the
    phrases; a document explaining the attack is indistinguishable, at the level
    of a regular expression, from the attack. This repository's own ADRs would
    fire this detector.

    So most of these report LOW: worth counting, worth combining with other
    signals, not worth refusing a result over on their own. The MEDIUM ones are
    the shapes that do not occur in prose *about* the subject — a literal
    `<system>` tag, a "new instructions:" header, an explicit instruction to
    conceal something from the user. Nobody writes those by accident.
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
"""Zero-width and soft-hyphen characters.

Two separate problems. A human reviewing the document does not see them, so an
instruction can hide in what looks like ordinary text. And a matcher does not
see *through* them, so `ig\u200bnore previous instructions` defeats every
pattern above while a model reads it as the sentence it is.

`\\ufeff` is included even though it is a legitimate byte-order mark, because it
has no business appearing in the middle of a tool result — and the screener
reports position, so a leading BOM is distinguishable from one buried in a word.
"""

BIDI_OVERRIDES: Final = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
"""Bidirectional *overrides* and *isolates* — not bidirectional text.

The distinction matters and getting it wrong would make this detector useless in
half the world. Arabic and Hebrew text legitimately contains directional marks
(`\\u200e`, `\\u200f`), and flagging those would fire on every honest document in
those languages. The characters here are different: they force a rendering order
regardless of content, which is what lets `\\u202e` display one string while the
underlying bytes say another — the trick behind the Trojan Source class of
attacks.

A tool result has no legitimate reason to contain one. HIGH confidence.
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
    """Remove what the two detectors above have already reported.

    **Order is load-bearing.** Stripping first would erase the evidence of
    obfuscation; matching first without stripping would miss every payload that
    used it. So the screener detects, records, *then* strips, and runs the
    remaining detectors over the cleaned text — which is why
    `ig\u200bnore previous instructions` produces two findings rather than none.
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
    """A markdown image pointing somewhere the deployment did not allow.

    The canonical exfiltration channel, and the reason it deserves its own
    detector rather than being folded into the URL check: **the model never
    sends anything.** It emits text. The *client* renders the markdown, the
    renderer fetches the image, and whatever was interpolated into the path or
    the query string arrives at a server the attacker controls. Nothing in the
    conversation looks like a network call, because from the model's side there
    wasn't one.

    HIGH, because an image URL is *fetched automatically* rather than clicked.
    A bare link needs a human to fall for it; this does not.
    """
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
    """Any URL whose host is not on the allow-list.

    An allow-list rather than a block-list, for the usual reason: a block-list
    enumerates what somebody already thought of, and an attacker's whole job is
    to think of something else.

    MEDIUM rather than HIGH. A legitimate document links to things — a ticket
    citing a vendor's docs is not an attack — so an empty allow-list would make
    this fire on nearly everything. It is a signal to combine, and it is most
    useful when a deployment has actually configured its hosts.
    """
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
MIN_DECODED = 12


def encoded_payload(text: str) -> Iterator[Finding]:
    """Base64 that decodes to something instruction-shaped.

    **Length alone is a terrible detector**, and saying so is the point. Long
    base64 runs are everywhere in legitimate text: JWTs, git hashes, embedded
    images, content digests, session identifiers. A rule that flagged them would
    fire constantly and be switched off, taking the useful half with it.

    So this decodes and re-screens. A run that decodes to bytes which are not
    text is ignored — that is an image or a hash, and it is none of this
    detector's business. A run that decodes to *readable text containing an
    instruction* is something else entirely: nobody base64-encodes a sentence by
    accident, and encoding one that says "ignore previous instructions" is not a
    coincidence anybody has to argue about.

    HIGH, because the decode step has already done the disambiguation that made
    the naive version useless.
    """
    for match in _BASE64_RUN.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) < MIN_DECODED:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Binary. An image, a digest, a key — not this detector's business.
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
    """A tool result naming a tool in this gateway's catalogue.

    **The one detector nobody but a gateway can write.** A model provider sees a
    conversation; an upstream sees its own API. Only the thing brokering for the
    whole estate knows that the document mock-a just returned mentions
    `mock-b__delete_record`, which mock-a has no legitimate reason to know
    exists — and which, if the model acts on it, is the injection working.

    Qualified names only (`upstream__tool`, ADR 0003), which is what keeps the
    false-positive rate near zero: a document containing the word "search" is
    ordinary, and one containing `mock-b__search` is a document that has read
    this gateway's catalogue.
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
