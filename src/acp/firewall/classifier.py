"""An optional model-based detector, behind the same interface as the patterns.

The pattern detectors (`acp.firewall.detectors`) are free, deterministic, and
explainable, and everything downstream relies on those properties. A classifier
is none of them: it is slow, its answer varies, and it cannot fully explain
itself. So it is added the only way that does not poison what the pattern layer
guarantees — as *one more detector that emits findings*, never as a decider:

- **It emits `Finding`s, exactly like a pattern.** It never refuses; detection
  and decision stay separate (ADR 0036), so its contribution is measurable as a
  false-positive rate rather than hidden inside a verdict.
- **Its confidence is capped at MEDIUM.** A model saying "this looks like an
  attack" is a weaker claim than a regex matching ``<system>`` literally. It is
  "unusual in ordinary text, cheap to explain" — never the HIGH that a
  deterministic match earns. On its own it should not enforce; it is the second
  signal that can promote a demoted pattern (task 48), not a first mover.
- **Absence is a first-class path.** The model service may be missing, down, or
  slow. Every one of those yields *no findings*, never an exception into the
  screening path — a firewall that fails closed on its optional layer is a
  firewall that a model outage takes offline. This is also why the client is
  injected: the classifier is fully testable with no model at all.
- **The model's output is untrusted input.** The text screened is hostile by
  premise, and so, therefore, is anything a model produces after reading it. The
  response is parsed defensively: an unexpected shape, an unknown family, or an
  attempt to talk to the parser yields no finding, not a crash and not a
  smuggled instruction.
- **The input is bounded before it is sent.** The screener already bounds text;
  the classifier bounds again to what it sends the model, because a hostile
  document should not be able to turn one screening into a megabyte of inference.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass

from acp.firewall.findings import Confidence, Family, Finding

logger = logging.getLogger(__name__)

MAX_CLASSIFIED_CHARS = 4000
"""How much of a document the classifier sends the model. Enough to judge, bounded
so a hostile document cannot inflate one screening into an unbounded inference."""

DETECTOR_NAME = "model_classifier"

# The confidence a model verdict is allowed to carry. A deliberate ceiling: a
# model's judgement is a weaker claim than a literal pattern match, and letting
# it report HIGH would let an opaque signal enforce on its own.
_MAX_CONFIDENCE = Confidence.MEDIUM


@dataclass(frozen=True, slots=True)
class Verdict:
    """A model's parsed answer: whether it judged the text an attack, and which
    family it named. ``family`` is ``None`` when the model abstained or named
    something outside the taxonomy."""

    is_attack: bool
    family: Family | None


ClassifyFn = Callable[[str], str]
"""The seam to the model: text in, raw model response out. Injected so the
classifier is testable with no Ollama, and so the transport (HTTP to a local
Ollama, or anything else) is not this module's concern."""


def parse_verdict(raw: str) -> Verdict:
    """Parse a model response into a verdict, defensively.

    The model is asked for JSON ``{"attack": bool, "family": str}``. Anything
    else — prose, malformed JSON, an unknown family, a field of the wrong type —
    is treated as an abstention, not an error. A classifier that raised on a
    surprising model response would be a denial of service triggered by the model
    it depends on.
    """
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
    """A model-backed detector. Emits at most one finding, capped at MEDIUM.

    ``classify`` is the injected seam to the model. When it is ``None`` the
    classifier is inert — the supported, tested state for a deployment without a
    model — and returns no findings.
    """

    classify_fn: ClassifyFn | None = None

    def classify(self, text: str) -> tuple[Finding, ...]:
        """The model's findings about ``text`` — empty when it is inert, when the
        model abstains, or when anything goes wrong reaching it."""
        if self.classify_fn is None:
            return ()

        bounded = text[:MAX_CLASSIFIED_CHARS]
        try:
            raw = self.classify_fn(bounded)
        except Exception:
            # Any failure reaching the model — timeout, connection refused, a
            # transport raising — is an absent signal, not a firewall error. The
            # pattern detectors have already run; the model simply adds nothing.
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
