"""The injection firewall: what an upstream said, screened before a model reads it.

Phase 5, and the phase the whole project is aimed at. Everything before this
constrains what an agent *may* do. This one addresses what makes an agent do the
wrong thing in the first place: a model that reads untrusted data and can also
take actions has no boundary between "what I was asked" and "words I happened to
read", and prompt injection is the top entry on the 2026 OWASP GenAI list for
exactly that reason.

Task 45 is the pattern layer only. It detects; it decides nothing. Provenance
framing is task 46, structured refusal is task 47, and the measured detection
and false-positive rates — the numbers that make any of this a claim worth
believing — are tasks 48 to 52.
"""

from acp.firewall.findings import Confidence, Family, Finding
from acp.firewall.screen import Screener, Screening, ScreenPolicy, screen_policy_for

__all__ = [
    "Confidence",
    "Family",
    "Finding",
    "ScreenPolicy",
    "Screener",
    "Screening",
    "screen_policy_for",
]
