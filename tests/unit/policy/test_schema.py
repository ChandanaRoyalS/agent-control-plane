"""Unit tests for the policy schema.

The load-bearing test is that `effect` has no default. Deny-by-default is only
real if a rule cannot be written that matches everything and silently allows it,
and the schema enforces that by refusing a rule with no effect at all — the
`effect` field is required precisely so the most dangerous omission is an error
rather than a guess.

Bad-input tests use ``model_validate`` with an untyped dict rather than direct
construction, matching ``tests/unit/upstream/test_config.py``: it exercises the
same path a YAML document takes and keeps a deliberately-invalid value from
being a static type error in the test itself.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from acp.policy import Effect, Policy, Rule


def test_effect_has_no_default_so_omitting_it_is_an_error() -> None:
    """The core of deny-by-default: a rule that forgot to say allow-or-deny is
    rejected, not silently treated as one of them."""
    with pytest.raises(ValidationError):
        Rule.model_validate({"name": "matches-everything"})


def test_effect_accepts_the_yaml_words() -> None:
    """A policy file spells the effect as the string `allow`/`deny`; the model
    accepts that and yields the enum."""
    assert Rule.model_validate({"name": "a", "effect": "allow"}).effect is Effect.ALLOW
    assert Rule.model_validate({"name": "b", "effect": "deny"}).effect is Effect.DENY


def test_an_unknown_effect_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate({"name": "a", "effect": "permit"})


def test_match_fields_default_to_match_anything() -> None:
    """An allow rule with no subjects/actors/tools matches every request. That
    is a legitimate value — a tool everyone may use — and safe only because the
    document default is deny, not because rules are forced to be specific."""
    rule = Rule(name="allow-all-the-things", effect=Effect.ALLOW)
    assert rule.subjects == ()
    assert rule.actors == ()
    assert rule.tools == ()


@pytest.mark.parametrize(
    "name",
    ["allow-search", "deny", "a1", "allow-search-for-support-agents"],
)
def test_valid_rule_names_are_accepted(name: str) -> None:
    assert Rule(name=name, effect=Effect.ALLOW).name == name


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("allow_search", id="underscore"),
        pytest.param("Allow-Search", id="uppercase"),
        pytest.param("-leading", id="leading-hyphen"),
        pytest.param("trailing-", id="trailing-hyphen"),
        pytest.param("double--hyphen", id="double-hyphen"),
        pytest.param("", id="empty"),
        pytest.param("a" * 49, id="too-long"),
    ],
)
def test_invalid_rule_names_are_rejected(name: str) -> None:
    with pytest.raises(ValidationError):
        Rule(name=name, effect=Effect.ALLOW)


def test_extra_fields_are_forbidden_on_a_rule() -> None:
    """A typo'd field name must fail loudly, not be silently ignored — a
    misspelled `tool` (singular) that vanished would produce a rule matching far
    more than intended."""
    bad: dict[str, Any] = {"name": "a", "effect": "allow", "tool": "mock-a__search"}
    with pytest.raises(ValidationError):
        Rule.model_validate(bad)


def test_rules_are_frozen() -> None:
    rule = Rule(name="a", effect=Effect.ALLOW)
    with pytest.raises(ValidationError):
        rule.name = "b"


def test_empty_policy_is_valid_and_means_deny_everything() -> None:
    """A truncated policy file should lock the doors, not fail to start. An empty
    rule set is a valid document that denies every request once the engine
    exists."""
    assert Policy().rules == ()


def test_policy_preserves_rule_order() -> None:
    """First-match-wins evaluation (task 33) depends on order, so the model must
    not reorder or dedupe the sequence it was given."""
    policy = Policy(
        rules=(
            Rule(name="deny-delete", effect=Effect.DENY),
            Rule(name="allow-crm", effect=Effect.ALLOW),
        )
    )
    assert [r.name for r in policy.rules] == ["deny-delete", "allow-crm"]


def test_duplicate_rule_names_are_rejected() -> None:
    """The audit log names the rule that decided a call, so two rules sharing a
    name make an incident review ambiguous."""
    with pytest.raises(ValidationError):
        Policy(
            rules=(
                Rule(name="allow-search", effect=Effect.ALLOW),
                Rule(name="allow-search", effect=Effect.DENY),
            )
        )


def test_extra_fields_are_forbidden_on_a_policy() -> None:
    bad: dict[str, Any] = {"rules": [], "default": "allow"}
    with pytest.raises(ValidationError):
        Policy.model_validate(bad)


# --- args field (task 37) ---


def test_args_defaults_to_empty() -> None:
    """A rule without args constrains no arguments — backward compatible."""
    rule = Rule(name="r", effect=Effect.ALLOW)
    assert rule.args == {}


def test_args_accepts_a_mapping_of_name_to_values() -> None:
    rule = Rule(
        name="r",
        effect=Effect.ALLOW,
        tools=("mock-a__read_document",),
        args={"doc_id": ("public-handbook", "public-faq")},
    )
    assert rule.args["doc_id"] == ("public-handbook", "public-faq")


def test_unknown_rule_field_is_still_forbidden_with_args_present() -> None:
    """extra=forbid still holds — args does not loosen the schema."""
    with pytest.raises(ValidationError):
        Rule(name="r", effect=Effect.ALLOW, argz={"x": ("y",)})  # type: ignore[call-arg]
