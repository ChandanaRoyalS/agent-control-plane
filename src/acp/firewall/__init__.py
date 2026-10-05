"""The injection firewall: upstream output screened before a model reads it.

Three layers: detectors (`screen`) only detect, so their false-positive rate is
measurable; provenance framing (`provenance`) frames every result and judges
nothing; the decision layer (`decision`) acts, on a deliberately high bar whose
evidence comes from `acp.corpus`.
"""

from acp.firewall.classifier import OllamaClassifier
from acp.firewall.decision import Firewall, Inspection, Mode, firewall_for
from acp.firewall.findings import Confidence, Family, Finding
from acp.firewall.ollama import ollama_classify
from acp.firewall.provenance import Fence, fence_for, frame
from acp.firewall.screen import Screener, Screening, ScreenPolicy, screen_policy_for

__all__ = [
    "Confidence",
    "Family",
    "Fence",
    "Finding",
    "Firewall",
    "Inspection",
    "Mode",
    "OllamaClassifier",
    "ScreenPolicy",
    "Screener",
    "Screening",
    "fence_for",
    "firewall_for",
    "frame",
    "ollama_classify",
    "screen_policy_for",
]
