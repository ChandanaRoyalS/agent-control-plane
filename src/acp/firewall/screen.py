"""Running every detector over one piece of text, within bounds.

Invisible and bidi characters are recorded before being stripped, then the other
detectors run on the cleaned text. Input beyond ``max_chars`` is not examined and
the truncation is reported. Screening never raises or decides; deciding is
`acp.firewall.decision`.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from typing import Final

from acp.firewall import detectors
from acp.firewall.classifier import DETECTOR_NAME as CLASSIFIER_NAME
from acp.firewall.classifier import OllamaClassifier
from acp.firewall.findings import DETECTOR_NAMES, Confidence, Family, Finding

logger = logging.getLogger(__name__)

MAX_SCREENED_CHARS: Final = 256 * 1024
"""Characters examined per text; the cap is reported via ``Screening.truncated``."""


@dataclass(frozen=True, slots=True)
class Screening:
    """Everything one pass observed."""

    findings: tuple[Finding, ...] = ()
    truncated: bool = False
    """Whether text exceeded the window; the decision layer treats this as a trigger."""

    scanned_chars: int = 0

    @property
    def clean(self) -> bool:
        """No findings *and* nothing left unexamined."""
        return not self.findings and not self.truncated

    def by_family(self) -> dict[Family, int]:
        counts: dict[Family, int] = {}
        for finding in self.findings:
            counts[finding.family] = counts.get(finding.family, 0) + 1
        return counts

    def highest(self) -> Confidence | None:
        """The strongest confidence present, or ``None``."""
        order = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)
        present = [f.confidence for f in self.findings]
        return max(present, key=order.index) if present else None


@dataclass(frozen=True)
class ScreenPolicy:
    """What this deployment considers ordinary.

    Empty defaults report every URL and never fire the tool-name detector.
    """

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    tools: frozenset[str] = field(default_factory=frozenset)
    max_chars: int = MAX_SCREENED_CHARS


class Screener:
    """Runs every detector, in the one order that makes obfuscation visible."""

    def __init__(
        self,
        policy: ScreenPolicy | None = None,
        *,
        classifier: OllamaClassifier | None = None,
    ) -> None:
        self._policy = policy or ScreenPolicy()
        # Optional; adds findings after the patterns (see acp.firewall.classifier).
        self._classifier = classifier

    @property
    def detector_names(self) -> tuple[str, ...]:
        """Which detectors this screener runs; a test compares it with `DETECTOR_NAMES`."""
        if self._classifier is None:
            return DETECTOR_NAMES
        return (*DETECTOR_NAMES, CLASSIFIER_NAME)

    def screen(self, text: str) -> Screening:
        """Every finding in ``text``, and whether all of it was examined."""
        if not text:
            return Screening()

        truncated = len(text) > self._policy.max_chars
        window = text[: self._policy.max_chars]

        # Obfuscation first, on the raw window: stripping destroys its evidence.
        found: list[Finding] = [
            *detectors.invisible_characters(window),
            *detectors.bidirectional_override(window),
        ]

        cleaned = detectors.strip_invisible(window)

        found.extend(detectors.instruction_override(cleaned))
        found.extend(detectors.external_image(cleaned, self._policy.allowed_hosts))
        found.extend(detectors.disallowed_url(cleaned, self._policy.allowed_hosts))
        found.extend(detectors.encoded_payload(cleaned))
        found.extend(detectors.tool_name_mention(cleaned, self._policy.tools))

        if self._classifier is not None:
            found.extend(self._classifier.classify(cleaned))

        if found or truncated:
            # One line per screening, not per finding, to avoid attacker-chosen amplification.
            logger.warning(
                "firewall.findings",
                extra={
                    "count": len(found),
                    "families": {str(k): v for k, v in _counts(found).items()},
                    "truncated": truncated,
                    "scanned_chars": len(window),
                },
            )

        return Screening(findings=tuple(found), truncated=truncated, scanned_chars=len(window))

    def screen_all(self, texts: Sequence[str]) -> Screening:
        """One merged screening over a result's text blocks.

        Offsets stay per-block and are only comparable within a block.
        """
        findings: list[Finding] = []
        truncated = False
        scanned = 0
        for text in texts:
            screening = self.screen(text)
            findings.extend(screening.findings)
            truncated = truncated or screening.truncated
            scanned += screening.scanned_chars
        return Screening(findings=tuple(findings), truncated=truncated, scanned_chars=scanned)


def _counts(findings: Sequence[Finding]) -> dict[Family, int]:
    counts: dict[Family, int] = {}
    for finding in findings:
        counts[finding.family] = counts.get(finding.family, 0) + 1
    return counts


def screen_policy_for(
    *, allowed_hosts: AbstractSet[str] = frozenset(), tools: AbstractSet[str] = frozenset()
) -> ScreenPolicy:
    return ScreenPolicy(allowed_hosts=frozenset(allowed_hosts), tools=frozenset(tools))
