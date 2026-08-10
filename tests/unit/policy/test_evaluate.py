"""Unit tests for the policy evaluator.

The evaluator is a pure function, so these tests are the whole of its contract:
first-match-wins, deny-by-default, membership matching with unset-means-any, and
the one edge that is easy to get wrong — a rule that names actors must not match
a request that has no actor.
"""

from __future__ import annotations

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


# --- argument-level rules (task 37) ---


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


def test_a_missing_constrained_argument_denies() -> None:
    """A rule that constrains an argument cannot match a call that omits it —
    'set means one of these' the same way a named actor cannot match None."""
    decision = evaluate(_arg_policy(), _principal(), "mock-a__read_document", {})
    assert decision.allowed is False


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
