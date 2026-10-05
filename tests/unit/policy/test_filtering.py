"""Unit tests for catalogue filtering.

``visible_tools`` is the visibility half of policy: a tool the caller could
never call is not shown. The tests pin that visibility asks the same question
the pre-dispatch check does (`could_ever_allow`, same qualified name), that
order is preserved, that the deny default hides an unmatched tool rather than
showing it, and that an argument-scoped rule never hides a tool some call to it
could reach (ADR 0072).
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


# ---------------------------------------------------------------------------
# Argument-scoped rules (ADR 0072): visible when some call could be permitted
# ---------------------------------------------------------------------------


def test_a_tool_granted_only_for_some_arguments_is_visible() -> None:
    """A listing has no arguments, and "may read the public dataset" is still
    a grant to the read tool. Hidden, the agent could never ask for the
    document it is entitled to."""
    policy = Policy(
        rules=(
            Rule(
                name="public-reads",
                effect=Effect.ALLOW,
                tools=("crm__read",),
                args={"dataset": ("public",)},
            ),
        )
    )
    assert [t.name for t in visible_tools(policy, _principal(), _tools("crm__read"))] == [
        "crm__read"
    ]


def test_an_argument_scoped_deny_in_front_of_an_allow_leaves_the_tool_visible() -> None:
    """The README's policy. ADR 0068 made the deny catch a call that omits its
    argument, which is right for a call and wrong for a listing: the tool
    vanished from the catalogue while calls to it with other arguments were
    served. The official client's first run found it."""
    policy = Policy(
        rules=(
            Rule(
                name="not-production",
                effect=Effect.DENY,
                tools=("crm__delete_record",),
                args={"dataset": ("production",)},
            ),
            Rule(name="deletes", effect=Effect.ALLOW, tools=("crm__delete_record",)),
        )
    )
    visible = visible_tools(policy, _principal(), _tools("crm__delete_record"))
    assert [t.name for t in visible] == ["crm__delete_record"]


def test_an_unconditional_deny_still_hides_the_tool() -> None:
    policy = Policy(
        rules=(
            Rule(name="no-deletes", effect=Effect.DENY, tools=("crm__delete_record",)),
            Rule(name="rest", effect=Effect.ALLOW),
        )
    )
    assert visible_tools(policy, _principal(), _tools("crm__delete_record", "crm__read")) == [
        ToolDefinition(name="crm__read")
    ]
