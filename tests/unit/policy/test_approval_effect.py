"""`require_approval`: a third policy effect that every old caller reads as "no".

The safety argument for how approvals were added is a shape, not a check:
`Decision.allowed` stayed a boolean and `requires_approval` is a separate flag,
so every consumer written before approvals existed asks `if decision.allowed`
and a held call answers `False`. **They fail closed by construction, without
being changed and without anybody having to remember to change them.**

Most of this file asserts that. The exceptions are the three places that had to
be taught the third value on purpose — the catalogue filter, the pre-dispatch
fast path, and the decision log — and each of those is a bug if it is missed,
in a different direction.
"""

from __future__ import annotations

import logging

import pytest

from acp.exceptions import PolicyDeniedError
from acp.identity.principal import Actor, Principal
from acp.policy.enforce import APPROVAL_EVENT, enforce_call
from acp.policy.evaluate import Verdict, evaluate
from acp.policy.filtering import visible_tools
from acp.policy.predispatch import could_ever_allow
from acp.policy.schema import Effect, Policy, Rule
from acp.upstream.models import ToolDefinition

TOOL = "crm__delete_record"
ISSUER = "https://idp.test"

GATED = Policy(rules=(Rule(name="approve-deletes", effect=Effect.REQUIRE_APPROVAL, tools=(TOOL,)),))


def principal(subject: str = "alice", actor: str | None = None) -> Principal:
    return Principal(
        subject=subject,
        issuer=ISSUER,
        actor=Actor(subject=actor) if actor is not None else None,
    )


# ---------------------------------------------------------------------------
# The shape that makes every old caller safe
# ---------------------------------------------------------------------------


def test_a_held_call_is_not_allowed() -> None:
    """**The whole safety argument in one assertion.** Approval is not
    permission; it is the absence of a denial pending a human."""
    decision = evaluate(GATED, principal(), TOOL)

    assert not decision.allowed
    assert decision.requires_approval
    assert decision.verdict is Verdict.APPROVAL


def test_allowed_and_requires_approval_are_never_both_true() -> None:
    """The invariant. A three-valued `allowed` would have made every existing
    `if decision.allowed` a truthiness bug waiting to be found in production."""
    policy = Policy(
        rules=(
            Rule(name="allow-search", effect=Effect.ALLOW, tools=("crm__search",)),
            Rule(name="approve-deletes", effect=Effect.REQUIRE_APPROVAL, tools=(TOOL,)),
            Rule(name="deny-rest", effect=Effect.DENY),
        )
    )

    for tool in ("crm__search", TOOL, "crm__export"):
        decision = evaluate(policy, principal(), tool)
        assert not (decision.allowed and decision.requires_approval)


def test_the_deny_default_never_asks_for_a_human() -> None:
    decision = evaluate(Policy(rules=()), principal(), TOOL)

    assert decision.verdict is Verdict.DENY
    assert decision.rule is None


def test_a_held_decision_names_the_rule_that_held_it() -> None:
    """An approval nobody can attribute to a rule is a question nobody can
    answer — the operator is being asked *why*, and the rule is the answer."""
    decision = evaluate(GATED, principal(), TOOL)

    assert decision.rule == "approve-deletes"
    assert "approve-deletes" in decision.reason
    assert "held for approval" in decision.reason


def test_first_match_wins_still_holds_with_three_effects() -> None:
    """A narrow `require_approval` in front of a broad allow reads the way an
    operator means it (ADR 0026)."""
    policy = Policy(
        rules=(
            Rule(
                name="approve-hard-deletes",
                effect=Effect.REQUIRE_APPROVAL,
                tools=(TOOL,),
                args={"hard": ("true",)},
            ),
            Rule(name="allow-crm", effect=Effect.ALLOW, tools=(TOOL,)),
        )
    )

    assert evaluate(policy, principal(), TOOL, {"hard": "true"}).requires_approval
    assert evaluate(policy, principal(), TOOL, {"hard": "false"}).allowed


# ---------------------------------------------------------------------------
# enforce_call — neither returns nor raises
# ---------------------------------------------------------------------------


def test_enforce_returns_the_decision_rather_than_raising() -> None:
    """A held call is neither permitted nor refused, so it cannot be expressed
    by returning or raising. The caller has to read the decision."""
    decision = enforce_call(GATED, principal(), TOOL)

    assert decision.requires_approval


def test_enforce_still_raises_for_a_real_denial() -> None:
    with pytest.raises(PolicyDeniedError):
        enforce_call(Policy(rules=()), principal(), TOOL)


def test_a_held_call_is_logged_under_its_own_event(caplog: pytest.LogCaptureFixture) -> None:
    """Its own event name, not `policy.denied`. A held call and a refused one
    are different things to count, alert on and explain, and an audit log that
    called them both denials would make an approval flow invisible."""
    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(GATED, principal(), TOOL, {"record_id": "x"})

    record = caplog.records[0]
    assert record.getMessage() == APPROVAL_EVENT
    assert vars(record)["decision"] == "approval"
    assert vars(record)["rule"] == "approve-deletes"


# ---------------------------------------------------------------------------
# The three places that had to be taught, and what breaks if they are not
# ---------------------------------------------------------------------------


def test_a_gated_tool_stays_in_the_catalogue() -> None:
    """**Hiding it would make the feature unreachable.** The agent is supposed
    to ask for this tool — that is what triggers the approval. A filter that
    kept "visible iff allowed" would hide it, the agent would never name it, the
    operator would never be asked, and the flow would never run."""
    tools = [ToolDefinition(name=TOOL, description="", inputSchema={})]

    assert visible_tools(GATED, principal(), tools) == tools


def test_a_denied_tool_is_still_hidden() -> None:
    """The other half: "not denied" is a widening, not an abandonment."""
    policy = Policy(rules=(Rule(name="no", effect=Effect.DENY, tools=(TOOL,)),))
    tools = [ToolDefinition(name=TOOL, description="", inputSchema={})]

    assert visible_tools(policy, principal(), tools) == []


def test_the_pre_dispatch_check_does_not_refuse_a_gated_call() -> None:
    """**A false refusal, and the kind ADR 0043 exists to prevent** — a call a
    human was about to approve, stopped at the header before anyone was asked,
    with no rule an operator could point at to explain it."""
    assert could_ever_allow(GATED, principal(), TOOL)


def test_the_pre_dispatch_check_still_refuses_what_nothing_permits() -> None:
    policy = Policy(rules=(Rule(name="no", effect=Effect.DENY, tools=(TOOL,)),))

    assert not could_ever_allow(policy, principal(), TOOL)


def test_an_argument_scoped_approval_does_not_let_the_fast_path_refuse() -> None:
    """The argument trap, with the third effect: the arguments are unknown at
    header time, so a rule that would hold *some* calls must not refuse *all* of
    them."""
    policy = Policy(
        rules=(
            Rule(
                name="approve-hard",
                effect=Effect.REQUIRE_APPROVAL,
                tools=(TOOL,),
                args={"hard": ("true",)},
            ),
        )
    )

    assert could_ever_allow(policy, principal(), TOOL)
