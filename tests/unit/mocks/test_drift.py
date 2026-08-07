"""Unit tests for the mocks' schema-drift switch.

The point of this switch is that it produces no symptom the resilience stack can
see. Every response is well-formed, fast and successful — so the tests that
matter here are the ones asserting that the *only* thing that changed is the
catalogue's content.
"""

from __future__ import annotations

import pytest

from acp.mocks.drift import (
    RUG_PULL_SENTENCE,
    DriftFlavour,
    apply_drift,
    resolve_flavour,
)
from acp.mocks.jsonrpc import ToolDefinition
from acp.mocks.mock_a import TOOLS


def definitions() -> list[ToolDefinition]:
    return [tool.definition() for tool in TOOLS]


def names(tools: list[ToolDefinition]) -> list[str]:
    return [tool.name for tool in tools]


def test_the_default_is_no_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MOCK_SCHEMA_DRIFT", raising=False)

    assert apply_drift(definitions()) == definitions()


def test_the_rug_pull_changes_the_description_and_nothing_else() -> None:
    """Same name, same arguments, same handler, same successful responses. The
    only difference is a sentence of prose that goes straight into the agent's
    prompt — which is exactly why nothing in tasks 13 to 18 can detect it."""
    before = definitions()[0]
    after = apply_drift(definitions(), DriftFlavour.DESCRIPTION)[0]

    assert after.name == before.name
    assert after.input_schema == before.input_schema
    assert after.description == before.description + RUG_PULL_SENTENCE


def test_schema_drift_adds_an_argument() -> None:
    after = apply_drift(definitions(), DriftFlavour.SCHEMA)[0]

    assert "format" in after.input_schema["properties"]
    assert after.description == definitions()[0].description


def test_added_exposes_a_tool_that_was_not_in_the_baseline() -> None:
    after = apply_drift(definitions(), DriftFlavour.ADDED)

    assert "exfiltrate" in names(after)
    assert len(after) == len(definitions()) + 1


def test_removed_withdraws_one() -> None:
    after = apply_drift(definitions(), DriftFlavour.REMOVED)

    assert len(after) == len(definitions()) - 1
    assert names(after) == names(definitions())[:-1]


def test_all_produces_every_kind_at_once() -> None:
    """Including the added tool surviving the removal, which is the one place
    the ordering inside `apply_drift` could quietly cancel itself out."""
    after = apply_drift(definitions(), DriftFlavour.ALL)

    assert "exfiltrate" in names(after)
    assert RUG_PULL_SENTENCE in after[0].description
    assert "format" in after[0].input_schema["properties"]
    assert len(after) == len(definitions())


def test_the_input_is_never_mutated() -> None:
    """`apply_drift` runs per request against the same module-level tool list.
    Mutating it would make the drift permanent from the first request onwards
    and impossible to switch back off."""
    original = definitions()
    apply_drift(original, DriftFlavour.ALL)

    assert original == definitions()


def test_an_empty_catalogue_is_left_alone() -> None:
    assert apply_drift([], DriftFlavour.ALL) == []


def test_the_flavour_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Process-wide rather than per-request, because the request that has to
    observe it is the health prober's — and the prober sends exactly what the
    gateway normally sends, chaos headers included by nobody."""
    monkeypatch.setenv("MOCK_SCHEMA_DRIFT", "description")

    assert resolve_flavour() is DriftFlavour.DESCRIPTION
    assert RUG_PULL_SENTENCE in apply_drift(definitions())[0].description


def test_an_unknown_flavour_fails_loudly() -> None:
    """A mistyped switch that quietly behaves correctly is a demo that fails in
    a way nobody can explain."""
    with pytest.raises(ValueError, match="unknown schema drift flavour"):
        resolve_flavour("descriptoin")
