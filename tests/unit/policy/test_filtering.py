"""Unit tests for catalogue filtering.

``visible_tools`` is the visibility half of policy: a tool the caller may not
call is not shown. The tests pin that visibility tracks callability exactly
(same evaluator, same qualified name), that order is preserved, and that the
deny default hides an unmatched tool rather than showing it.
"""

from __future__ import annotations

from acp.identity.principal import Actor, Principal
from acp.policy import Effect, Policy, Rule, visible_tools
from acp.policy.arguments import ArgConstraint
from acp.policy.predispatch import could_ever_allow
from acp.upstream.models import ToolDefinition

ISSUER = "https://idp.test"


def _principal(subject: str = "alice", actor: str | None = None) -> Principal:
    act = Actor(subject=actor) if actor is not None else None
    return Principal(subject=subject, issuer=ISSUER, actor=act)


def _tools(*names: str) -> list[ToolDefinition]:
    return [ToolDefinition(name=n) for n in names]


def test_only_allowed_tools_survive() -> None:
    policy = Policy(
        rules=(Rule(name="allow-search", effect=Effect.ALLOW, tools=("mock-a__search",)),)
    )
    catalogue = _tools("mock-a__search", "mock-a__delete", "mock-b__list")
    visible = visible_tools(policy, _principal(), catalogue)
    assert [t.name for t in visible] == ["mock-a__search"]


def test_deny_default_hides_everything_unmatched() -> None:
    """An empty policy shows nothing — the deny default applied to every tool,
    which is the safe direction for a catalogue."""
    visible = visible_tools(Policy(), _principal(), _tools("a__x", "b__y"))
    assert visible == []


def test_explicit_deny_hides_a_tool_a_broad_allow_would_show() -> None:
    """A narrow deny ahead of a broad allow hides exactly that tool and shows
    the rest — visibility mirrors first-match evaluation."""
    policy = Policy(
        rules=(
            Rule(name="deny-delete", effect=Effect.DENY, tools=("mock-a__delete",)),
            Rule(name="allow-all", effect=Effect.ALLOW),
        )
    )
    visible = visible_tools(policy, _principal(), _tools("mock-a__search", "mock-a__delete"))
    assert [t.name for t in visible] == ["mock-a__search"]


def test_order_is_preserved() -> None:
    """Catalogue order is a prompt-cache decision; filtering must not reorder."""
    policy = Policy(rules=(Rule(name="allow-all", effect=Effect.ALLOW),))
    names = ["z__last", "a__first", "m__middle"]
    visible = visible_tools(policy, _principal(), _tools(*names))
    assert [t.name for t in visible] == names


def test_visibility_is_per_principal() -> None:
    """Two principals see different catalogues from the same policy — the whole
    point."""
    policy = Policy(
        rules=(
            Rule(
                name="alice-only",
                effect=Effect.ALLOW,
                subjects=("alice",),
                tools=("mock-a__search",),
            ),
        )
    )
    catalogue = _tools("mock-a__search")
    assert [t.name for t in visible_tools(policy, _principal("alice"), catalogue)] == [
        "mock-a__search"
    ]
    assert visible_tools(policy, _principal("bob"), catalogue) == []


def test_empty_catalogue_stays_empty() -> None:
    policy = Policy(rules=(Rule(name="allow-all", effect=Effect.ALLOW),))
    assert visible_tools(policy, _principal(), []) == []


def test_an_argument_scoped_rule_keeps_its_tool_visible() -> None:
    """ADR 0031 said so; the implementation did the opposite for four tasks.

    `visible_tools` evaluated with an empty argument mapping, an argument
    constraint cannot hold for a call with no arguments, so every such rule fell
    through to the deny default and **hid** the tool — while `could_ever_allow`
    on the pre-dispatch path said the same tool was reachable. Nothing tested
    it, so the two disagreed quietly.

    Hiding it is the worse answer on its own terms: an agent that never sees the
    tool never names it, never triggers the approval, and the human is never
    asked.
    """
    policy = Policy(
        rules=(
            Rule(
                name="hold-production",
                effect=Effect.REQUIRE_APPROVAL,
                tools=("mock-b__delete_record",),
                args={"dataset": ArgConstraint(equals=("production",))},
            ),
            Rule(name="allow-delete", effect=Effect.ALLOW, tools=("mock-b__delete_record",)),
        )
    )
    catalogue = [ToolDefinition(name="mock-b__delete_record")]

    visible = visible_tools(policy, _principal(), catalogue)

    assert [tool.name for tool in visible] == ["mock-b__delete_record"]


def test_visibility_agrees_with_the_pre_dispatch_check() -> None:
    """The invariant the disagreement above violated: a tool the pre-dispatch
    check would let through to the body is a tool the catalogue shows."""
    policy = Policy(
        rules=(
            Rule(
                name="allow-public",
                effect=Effect.ALLOW,
                tools=("mock-a__read_document",),
                args={"doc_id": ArgConstraint(equals=("public",))},
            ),
        )
    )
    catalogue = [ToolDefinition(name="mock-a__read_document")]
    principal = _principal()

    visible = {tool.name for tool in visible_tools(policy, principal, catalogue)}

    for tool in catalogue:
        assert (tool.name in visible) is could_ever_allow(policy, principal, tool.name)
