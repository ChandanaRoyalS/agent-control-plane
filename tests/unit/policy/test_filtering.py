"""Unit tests for catalogue filtering.

``visible_tools`` is the visibility half of policy: a tool the caller may not
call is not shown. The tests pin that visibility tracks callability exactly
(same evaluator, same qualified name), that order is preserved, and that the
deny default hides an unmatched tool rather than showing it.
"""

from __future__ import annotations

from acp.identity.principal import Actor, Principal
from acp.policy import Effect, Policy, Rule, visible_tools
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
