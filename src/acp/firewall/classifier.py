"""An optional model-based detector that only emits findings (ADR 0036).

Its findings are capped at MEDIUM, so it can corroborate a pattern but never
enforce alone. Any failure reaching the model yields no findings (fail-open on
this optional layer, so a model outage cannot take the firewall offline). The
model's output is untrusted and parsed defensively, and input is truncated to
``MAX_CLASSIFIED_CHARS`` before it is sent.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass

from acp.firewall.findings import Confidence, Family, Finding

logger = logging.getLogger(__name__)

MAX_CLASSIFIED_CHARS = 4000
"""Characters sent to the model, bounded so one screening cannot be inflated."""

DETECTOR_NAME = "model_classifier"

# Ceiling: a HIGH model verdict would let an opaque signal enforce on its own.
_MAX_CONFIDENCE = Confidence.MEDIUM


@dataclass(frozen=True, slots=True)
class Verdict:
    """A parsed model answer; ``family`` is ``None`` on abstention or an unknown family."""

    is_attack: bool
    family: Family | None


ClassifyFn = Callable[[str], str]
"""Injected seam to the model: text in, raw response out (testable with no Ollama)."""


def parse_verdict(raw: str) -> Verdict:
    """Parse ``{"attack": bool, "family": str}``; any other shape abstains, never raises."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return Verdict(is_attack=False, family=None)
    if not isinstance(data, dict):
        return Verdict(is_attack=False, family=None)

    is_attack = data.get("attack")
    if not isinstance(is_attack, bool):
        return Verdict(is_attack=False, family=None)

    family: Family | None = None
    raw_family = data.get("family")
    if isinstance(raw_family, str):
        try:
            family = Family(raw_family)
        except ValueError:
            family = None

    return Verdict(is_attack=is_attack, family=family)


@dataclass(frozen=True, slots=True)
class OllamaClassifier:
    """A model-backed detector emitting at most one MEDIUM finding.

    With ``classify_fn`` ``None`` it is inert and returns no findings (supported).
    """

    classify_fn: ClassifyFn | None = None

    def classify(self, text: str) -> tuple[Finding, ...]:
        """Findings for ``text``; empty when inert, on abstention, or on any model error."""
        if self.classify_fn is None:
            return ()

        bounded = text[:MAX_CLASSIFIED_CHARS]
        try:
            raw = self.classify_fn(bounded)
        except Exception:
            # Any transport failure is an absent signal, not a firewall error.
            logger.debug("classifier.unavailable", exc_info=True)
            return ()

        verdict = parse_verdict(raw)
        if not verdict.is_attack or verdict.family is None:
            return ()

        return (
            Finding(
                detector=DETECTOR_NAME,
                family=verdict.family,
                confidence=_MAX_CONFIDENCE,
                evidence=bounded[:80],
            ),
        )
