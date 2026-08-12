"""The Ollama transport, exercised with a mocked HTTP client.

What a live model returns is task 52's concern; what this module does with a
response is testable now: it builds a fenced prompt, sends the shape Ollama
expects, extracts the model text, and copes with a response missing the field.
"""

from __future__ import annotations

import json

import httpx

from acp.firewall.ollama import DEFAULT_MODEL, _build_prompt, ollama_classify


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
