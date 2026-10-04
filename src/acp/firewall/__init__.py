"""The injection firewall: what an upstream said, screened before a model reads it.

The layer the whole project is aimed at. Everything before this
constrains what an agent *may* do. This one addresses what makes an agent do the
wrong thing in the first place: a model that reads untrusted data and can also
take actions has no boundary between "what I was asked" and "words I happened to
read", and prompt injection is the top entry on the 2026 OWASP GenAI list for
exactly that reason.

Three layers, built in this order for a reason. The detectors (`screen`) detect
and decide nothing, so their false-positive rate can be measured rather than
inferred from incidents. Provenance framing (`provenance`) frames every result
and judges nothing, so it has no error rate to measure. The decision layer
(`decision`) is the first that acts — and it acts on a bar set deliberately
high, because the numbers that would justify lowering it come from the corpora
and the evaluation harness in `acp.corpus`.
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
