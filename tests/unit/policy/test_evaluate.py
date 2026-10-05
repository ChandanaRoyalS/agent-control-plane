"""Unit tests for the policy evaluator.

The evaluator is a pure function, so these tests are the whole of its contract:
first-match-wins, deny-by-default, membership matching with unset-means-any, and
the one edge that is easy to get wrong — a rule that names actors must not match
a request that has no actor.
"""

from __future__ import annotations

import pytest

from acp.identity.principal import Actor, Principal
from acp.policy import Decision, Effect, Policy, Rule, evaluate

ISSUER = "https://idp.test"


def _principal(subject: str = "alice", actor: str | None = None) -> Principal:
    act = Actor(subject=actor) if actor is not None else None
    return Principal(subject=subject, issuer=ISSUER, actor=act)


def test_no_rules_denies_by_default() -> None:
    """An empty policy denies everything, and the denial names no rule."""
    decision = evaluate(Policy(), _principal(), "mock-a__search")
    assert decision.allowed is False
    assert decision.rule is None
    assert "default" in decision.reason


def test_no_matching_rule_denies_by_default() -> None:
    """A policy with rules that do not match this request still falls through to
    the deny default — the presence of allow rules for others grants nothing."""
    policy = Policy(rules=(Rule(name="allow-bob", effect=Effect.ALLOW, subjects=("bob",)),))
    decision = evaluate(policy, _principal(subject="alice"), "mock-a__search")
    assert decision.allowed is False
    assert decision.rule is None


def test_a_matching_allow_permits_and_names_the_rule() -> None:
    policy = Policy(
        rules=(Rule(name="allow-search", effect=Effect.ALLOW, tools=("mock-a__search",)),)
    )
    decision = evaluate(policy, _principal(), "mock-a__search")
    assert decision == Decision(allowed=True, rule="allow-search")


def test_a_matching_deny_refuses_and_names_the_rule() -> None:
    policy = Policy(
        rules=(Rule(name="deny-delete", effect=Effect.DENY, tools=("mock-a__delete",)),)
    )
    decision = evaluate(policy, _principal(), "mock-a__delete")
    assert decision.allowed is False
    assert decision.rule == "deny-delete"


def test_first_match_wins_deny_before_allow() -> None:
    """A narrow deny placed ahead of a broad allow wins — the whole point of an
    explicit deny effect and of ordered evaluation."""
    policy = Policy(
        rules=(
            Rule(name="deny-delete", effect=Effect.DENY, tools=("mock-a__delete",)),
            Rule(name="allow-all-crm", effect=Effect.ALLOW),
        )
    )
    assert evaluate(policy, _principal(), "mock-a__delete").rule == "deny-delete"
    # a different tool falls through the deny to the broad allow
    assert evaluate(policy, _principal(), "mock-a__search").rule == "allow-all-crm"


def test_first_match_wins_allow_before_deny() -> None:
    """Order is literal: an allow ahead of a deny for the same tool allows. The
    engine does not privilege deny — it privileges position."""
    policy = Policy(
        rules=(
            Rule(name="allow-search", effect=Effect.ALLOW, tools=("mock-a__search",)),
            Rule(name="deny-search", effect=Effect.DENY, tools=("mock-a__search",)),
        )
    )
    assert evaluate(policy, _principal(), "mock-a__search").rule == "allow-search"


def test_unset_fields_match_anything() -> None:
    """A rule with no match fields matches every request — safe only because the
    default is deny, and useful for a blanket allow or deny."""
    policy = Policy(rules=(Rule(name="allow-everything", effect=Effect.ALLOW),))
    assert evaluate(policy, _principal(subject="anyone"), "any__tool").allowed is True


def test_all_set_fields_must_match_anded() -> None:
    """subjects AND tools: a rule matches only when both hold. Matching the
    subject but not the tool does not match the rule."""
    policy = Policy(
        rules=(
            Rule(
                name="alice-search",
                effect=Effect.ALLOW,
                subjects=("alice",),
                tools=("mock-a__search",),
            ),
        )
    )
    assert evaluate(policy, _principal("alice"), "mock-a__search").allowed is True
    # right subject, wrong tool -> falls through to deny
    assert evaluate(policy, _principal("alice"), "mock-a__delete").rule is None
    # wrong subject, right tool -> falls through to deny
    assert evaluate(policy, _principal("bob"), "mock-a__search").rule is None


def test_subject_membership() -> None:
    policy = Policy(
        rules=(Rule(name="allow-team", effect=Effect.ALLOW, subjects=("alice", "bob")),)
    )
    assert evaluate(policy, _principal("alice"), "t").allowed is True
    assert evaluate(policy, _principal("bob"), "t").allowed is True
    assert evaluate(policy, _principal("carol"), "t").allowed is False


def test_actor_matching_when_delegated() -> None:
    policy = Policy(
        rules=(Rule(name="allow-agent", effect=Effect.ALLOW, actors=("acp-reporting-agent",)),)
    )
    delegated = _principal("alice", actor="acp-reporting-agent")
    assert evaluate(policy, delegated, "t").allowed is True
    other_agent = _principal("alice", actor="some-other-agent")
    assert evaluate(policy, other_agent, "t").rule is None


def test_a_rule_naming_actors_does_not_match_a_request_with_no_actor() -> None:
    """The edge that is easy to get wrong: `actors: [x]` means 'the actor must be
    x', and a non-delegated request has no actor, so it cannot satisfy that. It
    falls through to deny rather than matching as if the field were unset."""
    policy = Policy(rules=(Rule(name="allow-agent", effect=Effect.ALLOW, actors=("acp-agent",)),))
    non_delegated = _principal("alice", actor=None)
    decision = evaluate(policy, non_delegated, "t")
    assert decision.allowed is False
    assert decision.rule is None


def test_decision_reason_text() -> None:
    assert "default" in Decision(allowed=False, rule=None).reason
    assert Decision(allowed=True, rule="r").reason == "allowed by rule 'r'"
    assert Decision(allowed=False, rule="r").reason == "denied by rule 'r'"


# --- argument-level rules ---


def _arg_policy() -> Policy:
    return Policy(
        rules=(
            Rule(
                name="public-docs-only",
                effect=Effect.ALLOW,
                tools=("mock-a__read_document",),
                args={"doc_id": ("public-handbook", "public-faq")},
            ),
        )
    )


def test_a_matching_argument_allows() -> None:
    decision = evaluate(
        _arg_policy(), _principal(), "mock-a__read_document", {"doc_id": "public-handbook"}
    )
    assert decision.allowed is True
    assert decision.rule == "public-docs-only"


def test_an_argument_value_outside_the_set_denies() -> None:
    """The tool and subject match, but the argument value is not allowed — the
    rule does not match, so the request falls through to the deny default."""
    decision = evaluate(
        _arg_policy(), _principal(), "mock-a__read_document", {"doc_id": "secret-memo"}
    )
    assert decision.allowed is False
    assert decision.rule is None


def test_a_missing_constrained_argument_does_not_earn_an_allow() -> None:
    """An allow that constrains an argument cannot match a call that omits it —
    'set means one of these' the same way a named actor cannot match None."""
    decision = evaluate(_arg_policy(), _principal(), "mock-a__read_document", {})
    assert decision.allowed is False


# ---------------------------------------------------------------------------
# ADR 0068: a restriction reads its constraint fail-closed
# ---------------------------------------------------------------------------

DELETE = "crm__delete_record"


def _restriction(effect: Effect = Effect.DENY) -> Policy:
    """The natural shape, and the one an outside review bypassed: a narrow
    restriction on one argument value, a broad allow for the tool behind it."""
    return Policy(
        rules=(
            Rule(
                name="not-production",
                effect=effect,
                tools=(DELETE,),
                args={"dataset": ("production",)},
            ),
            Rule(name="deletes", effect=Effect.ALLOW, tools=(DELETE,)),
        )
    )


@pytest.mark.parametrize(
    "dataset",
    [
        "Production",
        "PRODUCTION",
        " production",
        "production ",
        "production\t",
        "\uff50roduction",  # full-width p: NFKC-equivalent, visually identical
        ["production"],
        {"name": "production"},
        None,
    ],
    ids=[
        "title",
        "upper",
        "lead-space",
        "trail-space",
        "tab",
        "fullwidth",
        "list",
        "object",
        "null",
    ],
)
def test_a_deny_is_not_cleared_by_respelling_its_argument(dataset: object) -> None:
    """Every variant a client could send that the upstream would read as
    'production' - or could not read at all - stays denied. Before ADR 0068
    each of these fell through to the allow."""
    decision = evaluate(_restriction(), _principal(), DELETE, {"dataset": dataset})

    assert decision.allowed is False
    assert decision.rule == "not-production"


def test_a_deny_is_not_cleared_by_omitting_its_argument() -> None:
    """The cheapest bypass of all: send nothing and let the upstream default
    decide. A restriction on a value the call did not name still holds."""
    decision = evaluate(_restriction(), _principal(), DELETE, {})

    assert decision.allowed is False
    assert decision.rule == "not-production"


def test_a_deny_is_cleared_by_a_readable_different_value() -> None:
    decision = evaluate(_restriction(), _principal(), DELETE, {"dataset": "staging"})

    assert decision.allowed is True
    assert decision.rule == "deletes"


def test_a_hold_for_approval_reads_its_argument_the_same_way() -> None:
    """`require_approval` is the other restriction: a variant that slipped past
    it would skip the human, which is the whole control (ADR 0048)."""
    policy = _restriction(Effect.REQUIRE_APPROVAL)

    held = evaluate(policy, _principal(), DELETE, {"dataset": "PRODUCTION"})
    omitted = evaluate(policy, _principal(), DELETE, {})
    cleared = evaluate(policy, _principal(), DELETE, {"dataset": "staging"})

    assert held.requires_approval
    assert held.rule == "not-production"
    assert omitted.requires_approval
    assert omitted.rule == "not-production"
    assert cleared.allowed
    assert cleared.rule == "deletes"


def test_an_allow_still_requires_the_exact_value() -> None:
    """The asymmetry is the point. A grant is earned precisely: `Public` is not
    `public` to an allow, because widening a grant by case folding would be the
    fail-open reading of the same rule."""
    policy = _arg_policy()

    assert not evaluate(policy, _principal(), "mock-a__read_document", {"doc_id": "Public"}).allowed
    assert not evaluate(
        policy, _principal(), "mock-a__read_document", {"doc_id": "public "}
    ).allowed
    assert not evaluate(
        policy, _principal(), "mock-a__read_document", {"doc_id": ["public"]}
    ).allowed


def test_a_boolean_argument_compares_as_json_spells_it() -> None:
    """`true` in the policy must match the JSON `true` a client sends. Python's
    `str(True)` is `True`, and the old comparison never matched."""
    policy = Policy(
        rules=(
            Rule(
                name="dry-runs", effect=Effect.ALLOW, tools=(DELETE,), args={"dry_run": ("true",)}
            ),
        )
    )

    assert evaluate(policy, _principal(), DELETE, {"dry_run": True}).allowed
    assert not evaluate(policy, _principal(), DELETE, {"dry_run": False}).allowed
    assert not evaluate(policy, _principal(), DELETE, {"dry_run": "True"}).allowed


def test_unset_args_matches_any_call() -> None:
    """A rule with no argument constraints matches regardless of arguments — the
    field is backward-compatible with every pre-task-37 rule."""
    policy = Policy(rules=(Rule(name="any", effect=Effect.ALLOW, tools=("mock-a__search",)),))
    assert evaluate(policy, _principal(), "mock-a__search", {"q": "anything"}).allowed
    assert evaluate(policy, _principal(), "mock-a__search").allowed


def test_argument_values_compare_by_string_form() -> None:
    """Policy values are strings; a numeric or boolean argument matches by its
    string form, keeping the exact-match model predictable across JSON types."""
    policy = Policy(
        rules=(
            Rule(
                name="limit-ten",
                effect=Effect.ALLOW,
                tools=("mock-a__search",),
                args={"limit": ("10",)},
            ),
        )
    )
    assert evaluate(policy, _principal(), "mock-a__search", {"limit": 10}).allowed
    assert not evaluate(policy, _principal(), "mock-a__search", {"limit": 20}).allowed


def test_multiple_constrained_arguments_are_anded() -> None:
    """Every constrained argument must hold — like the other match fields."""
    policy = Policy(
        rules=(
            Rule(
                name="two-args",
                effect=Effect.ALLOW,
                tools=("mock-a__read_document",),
                args={"doc_id": ("public",), "format": ("pdf",)},
            ),
        )
    )
    assert evaluate(
        policy, _principal(), "mock-a__read_document", {"doc_id": "public", "format": "pdf"}
    ).allowed
    assert not evaluate(
        policy, _principal(), "mock-a__read_document", {"doc_id": "public", "format": "docx"}
    ).allowed


@pytest.mark.parametrize(
    "tool",
    ["crm__Delete_Record", "CRM__DELETE_RECORD", "crm__delete_record ", " crm__delete_record"],
)
def test_a_tool_level_deny_is_not_cleared_by_respelling_the_tool(tool: str) -> None:
    """W11 of the external review. Whether an upstream honours the variant is
    its business; whether the gateway's restriction does is this one's."""
    policy = Policy(
        rules=(
            Rule(name="no-deletes", effect=Effect.DENY, tools=(DELETE,)),
            Rule(name="everything", effect=Effect.ALLOW),
        )
    )

    decision = evaluate(policy, _principal(), tool)

    assert decision.allowed is False
    assert decision.rule == "no-deletes"


def test_a_tool_level_allow_still_needs_the_exact_name() -> None:
    policy = Policy(rules=(Rule(name="deletes", effect=Effect.ALLOW, tools=(DELETE,)),))

    assert not evaluate(policy, _principal(), "crm__Delete_Record").allowed
