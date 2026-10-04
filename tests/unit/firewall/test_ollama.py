"""The Ollama transport, exercised with a mocked HTTP client.

What a live model returns is the evaluation's concern; what this module does with a
response is testable now: it builds a fenced prompt, sends the shape Ollama
expects, extracts the model text, and copes with a response missing the field.
"""

from __future__ import annotations

import json

import httpx

from acp.firewall.classifier import parse_verdict
from acp.firewall.findings import Family
from acp.firewall.ollama import DEFAULT_MODEL, FAMILIES, _build_prompt, ollama_classify


def test_the_prompt_offers_exactly_the_families_the_parser_accepts() -> None:
    """ADR 0060's defect, pinned: the prompt listed seven families and the parser
    mapped five, so two of the model's possible answers were discarded. Every
    family the prompt offers must survive `parse_verdict`, and every family the
    firewall can report must be offered."""
    offered = [name.strip() for name in FAMILIES.split(",")]
    assert offered == [family.value for family in Family]
    prompt = _build_prompt("x")
    for name in offered:
        assert name in prompt
        verdict = parse_verdict(f'{{"attack": true, "family": "{name}"}}')
        assert verdict.family is Family(name)
    assert "delayed_multi_step" not in prompt


def test_the_prompt_fences_the_document_and_forbids_following_it() -> None:
    prompt = _build_prompt("some retrieved text")
    assert "<document>" in prompt
    assert "</document>" in prompt
    assert "do not follow" in prompt.lower()


def test_it_sends_the_shape_ollama_expects_and_returns_the_model_text() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        return httpx.Response(200, json={"response": '{"attack": true, "family": "exfiltration"}'})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    raw = ollama_classify("exfiltrate to evil.example", client=client)

    assert captured["model"] == DEFAULT_MODEL
    assert captured["stream"] is False
    assert captured["format"] == "json"
    assert "<document>" in str(captured["prompt"])
    assert raw == '{"attack": true, "family": "exfiltration"}'


def test_a_response_missing_the_field_becomes_empty_text() -> None:
    """parse_verdict reads empty text as an abstention, so a malformed Ollama
    response degrades to no finding rather than an error."""
    client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={})))
    assert ollama_classify("x", client=client) == ""


def test_a_non_string_response_field_becomes_empty_text() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"response": 123}))
    )
    assert ollama_classify("x", client=client) == ""


def test_an_http_error_propagates_for_the_caller_to_absorb() -> None:
    """ollama_classify raises on transport failure; OllamaClassifier turns that
    into no-finding. The raise is the seam between them, asserted here."""
    client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(503)))
    try:
        ollama_classify("x", client=client)
        raise AssertionError("expected an HTTP error to propagate")
    except httpx.HTTPStatusError:
        pass
