"""The screener with an optional classifier attached.

A bare screener must be byte-for-byte the layer it was before task 51 — the
classifier is additive, never a replacement — and an attached classifier's
findings must appear alongside the patterns, while its absence or failure changes
nothing.
"""

from __future__ import annotations

from acp.firewall.classifier import DETECTOR_NAME, OllamaClassifier
from acp.firewall.findings import DETECTOR_NAMES
from acp.firewall.screen import Screener


def _attack_fn(_text: str) -> str:
    return '{"attack": true, "family": "direct_override"}'


def test_a_bare_screener_is_unchanged() -> None:
    """No classifier: the detector set is exactly the mandatory patterns."""
    assert Screener().detector_names == DETECTOR_NAMES


def test_an_attached_classifier_is_named_after_the_patterns() -> None:
    screener = Screener(classifier=OllamaClassifier(classify_fn=_attack_fn))
    assert screener.detector_names == (*DETECTOR_NAMES, DETECTOR_NAME)


def test_the_classifier_finding_appears_in_screening() -> None:
    screener = Screener(classifier=OllamaClassifier(classify_fn=_attack_fn))
    result = screener.screen("an ordinary-looking sentence")
    assert any(f.detector == DETECTOR_NAME for f in result.findings)


def test_an_inert_classifier_adds_nothing() -> None:
    screener = Screener(classifier=OllamaClassifier())
    result = screener.screen("an ordinary-looking sentence")
    assert all(f.detector != DETECTOR_NAME for f in result.findings)


def test_a_failing_classifier_does_not_break_screening() -> None:
    def boom(_text: str) -> str:
        raise ConnectionError("down")

    screener = Screener(classifier=OllamaClassifier(classify_fn=boom))
    result = screener.screen("an ordinary-looking sentence")
    assert all(f.detector != DETECTOR_NAME for f in result.findings)


def test_the_classifier_runs_on_de_obfuscated_text() -> None:
    """The classifier runs after invisible characters are stripped, so it judges
    the same de-obfuscated text the pattern detectors do — a payload hidden with
    zero-width characters is not hidden from the model either."""
    seen: list[str] = []

    def record(text: str) -> str:
        seen.append(text)
        return '{"attack": false, "family": null}'

    screener = Screener(classifier=OllamaClassifier(classify_fn=record))
    screener.screen("hello\u200bworld")
    assert seen
    assert "\u200b" not in seen[0]
