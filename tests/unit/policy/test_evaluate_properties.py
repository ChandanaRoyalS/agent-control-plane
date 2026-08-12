"""Property-based tests over the policy evaluator.

`test_evaluate.py` covers the cases somebody thought of. This covers the ones
nobody did, which is where a precedence bug lives: the evaluator's contract is
four interacting rules — deny by default, first match wins, unset matches
anything, set fields are ANDed — and interacting rules are exactly what
example-based tests under-cover, because an example can only ever exercise one
combination at a time.

**The invariants asserted here are ADR 0026's, not the task list's.** The plan
says to assert "deny always beats allow"; ADR 0026 considered deny-overrides
*and rejected it* in favour of first-match-wins, because "allow this narrow
thing even though a broad deny covers it" is inexpressible otherwise. So a deny
listed after a matching allow does **not** win, and a property asserting it did
would be testing a design this project deliberately did not build. Where the
plan and an accepted ADR disagree, the ADR is the contract.

**The alphabets are deliberately tiny.** Drawing subjects and tools from three
values each is what makes rules actually match — with free text, Hypothesis
would generate policies whose rules never fire and every case would fall through
to the deny default, testing one branch very thoroughly and nothing else.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from acp.identity.principal import Actor, Principal
from acp.policy.evaluate import evaluate
from acp.policy.schema import Effect, Policy, Rule

ISSUER = "https://idp.test"

SUBJECTS = ("alice", "bob", "carol")
ACTORS = ("agent-research", "agent-support")
TOOLS = ("mock-a__search", "mock-a__create_ticket", "mock-b__delete_record")
ARG_VALUES = ("public", "secret")

subjects = st.sampled_from(SUBJECTS)
actors = st.sampled_from(ACTORS)
tools = st.sampled_from(TOOLS)


def _freeze(values: list[str]) -> tuple[str, ...]:
    """Explicitly typed rather than passing ``tuple`` to ``.map``.

    ``.map(tuple)`` infers ``tuple[Any, ...]``, which `mypy --strict` rejects
    against the declared return type — a failure that would only appear on a
    machine where the strategies actually type-check.
    """
    return tuple(values)


def _subset(values: tuple[str, ...]) -> st.SearchStrategy[tuple[str, ...]]:
    """A possibly-empty selection. Empty means "matches anything", which is the
    case most likely to interact badly with the others, so it must be drawn
    often rather than as a rare edge."""
    return st.lists(st.sampled_from(values), unique=True, max_size=len(values)).map(_freeze)


@st.composite
def rules(draw: st.DrawFn, index: int = 0) -> Rule:
    return Rule(
        name=f"r{index}-{draw(st.integers(min_value=0, max_value=999))}",
        effect=draw(st.sampled_from([Effect.ALLOW, Effect.DENY])),
        subjects=draw(_subset(SUBJECTS)),
        actors=draw(_subset(ACTORS)),
        tools=draw(_subset(TOOLS)),
        args=draw(
            st.dictionaries(
                st.sampled_from(["doc_id"]),
                st.lists(st.sampled_from(ARG_VALUES), unique=True, min_size=1).map(_freeze),
                max_size=1,
            )
        ),
    )


@st.composite
def policies(draw: st.DrawFn, max_rules: int = 5) -> Policy:
    """A policy whose rule names are unique, because the schema requires it."""
    count = draw(st.integers(min_value=0, max_value=max_rules))
    drawn = [draw(rules(index)) for index in range(count)]
    return Policy(rules=tuple(drawn))


@st.composite
def requests(draw: st.DrawFn) -> tuple[Principal, str, dict[str, object]]:
    actor = draw(st.one_of(st.none(), actors))
    principal = Principal(
        subject=draw(subjects),
        issuer=ISSUER,
        actor=Actor(subject=actor) if actor is not None else None,
    )
    arguments: dict[str, object] = {}
    if draw(st.booleans()):
        arguments["doc_id"] = draw(st.sampled_from(ARG_VALUES))
    return principal, draw(tools), arguments


# ---------------------------------------------------------------------------
# The four invariants ADR 0026 commits to
# ---------------------------------------------------------------------------


@given(policy=policies(), request=requests())
def test_an_allow_always_names_the_rule_that_granted_it(
    policy: Policy, request: tuple[Principal, str, dict[str, object]]
) -> None:
    """ADR 0026: "`allowed is True` with `rule is None` is a state that cannot
    occur." It is the property the audit log rests on — an allow nobody can
    attribute to a rule is a permission nobody can explain or revoke."""
    principal, tool, arguments = request

    decision = evaluate(policy, principal, tool, arguments)

    if decision.allowed:
        assert decision.rule is not None


@given(policy=policies(), request=requests())
def test_a_decision_naming_no_rule_is_always_a_denial(
    policy: Policy, request: tuple[Principal, str, dict[str, object]]
) -> None:
    """The same invariant from the other side: the absence of a rule is the deny
    default (ADR 0025), never a permission."""
    principal, tool, arguments = request

    decision = evaluate(policy, principal, tool, arguments)

    if decision.rule is None:
        assert not decision.allowed


@given(request=requests())
def test_an_empty_policy_denies_everything(
    request: tuple[Principal, str, dict[str, object]],
) -> None:
    """Deny by default is structural: it is what happens when the loop finds
    nothing, not a rule somebody has to remember to write."""
    principal, tool, arguments = request

    decision = evaluate(Policy(rules=()), principal, tool, arguments)

    assert not decision.allowed
    assert decision.rule is None


@given(policy=policies(), request=requests())
def test_the_decision_is_the_first_matching_rule(
    policy: Policy, request: tuple[Principal, str, dict[str, object]]
) -> None:
    """First match wins, asserted against an independent scan.

    The oracle re-derives "which rule should decide" by walking the list in
    order, so a change that made the engine privilege deny over allow — the
    design ADR 0026 rejected — fails here rather than passing quietly because
    the examples happened to list denies first.
    """
    principal, tool, arguments = request
    decision = evaluate(policy, principal, tool, arguments)

    expected = next(
        (rule for rule in policy.rules if _matches(rule, principal, tool, arguments)),
        None,
    )

    if expected is None:
        assert decision.rule is None
    else:
        assert decision.rule == expected.name
        assert decision.allowed is (expected.effect is Effect.ALLOW)


@given(policy=policies(), request=requests())
def test_a_deny_after_a_matching_allow_does_not_win(
    policy: Policy, request: tuple[Principal, str, dict[str, object]]
) -> None:
    """The property that pins the design decision itself.

    Appending a deny that matches everything cannot change a decision that a
    rule already made. This is the concrete form of "the engine privileges
    position, not effect" — and it would fail immediately under deny-overrides,
    which is exactly why it is written down.
    """
    principal, tool, arguments = request
    before = evaluate(policy, principal, tool, arguments)
    if before.rule is None:
        return  # nothing matched, so there is no earlier decision to preserve

    catch_all_deny = Rule(name="zzz-catch-all", effect=Effect.DENY)
    after = evaluate(Policy(rules=(*policy.rules, catch_all_deny)), principal, tool, arguments)

    assert after.rule == before.rule
    assert after.allowed == before.allowed


@given(policy=policies(), request=requests(), extra=rules(99))
def test_appending_a_rule_cannot_change_an_existing_decision(
    policy: Policy,
    request: tuple[Principal, str, dict[str, object]],
    extra: Rule,
) -> None:
    """The operational guarantee that makes editing a policy safe.

    Because first match wins, a rule appended at the end can only affect
    requests that were previously falling through to the deny default. Nothing
    already allowed can become denied, and nothing already denied *by a rule*
    can become allowed. That is the property the policy simulator reports
    against, and it is why "add a rule at the bottom" is a low-risk edit.
    """
    principal, tool, arguments = request
    before = evaluate(policy, principal, tool, arguments)
    if before.rule is None:
        return

    after = evaluate(Policy(rules=(*policy.rules, extra)), principal, tool, arguments)

    assert after.rule == before.rule
    assert after.allowed == before.allowed


@given(policy=policies(), request=requests())
def test_a_rule_naming_actors_never_matches_a_request_without_one(
    policy: Policy, request: tuple[Principal, str, dict[str, object]]
) -> None:
    """ADR 0026 calls this "the one edge worth stating out loud": a missing
    actor satisfies "unset means any" but not "set means one of these".
    Treating it as a wildcard would let a rule scoped to one agent match a
    request made by none."""
    principal, tool, arguments = request
    if principal.actor is not None:
        return

    decision = evaluate(policy, principal, tool, arguments)

    if decision.rule is not None:
        deciding = next(rule for rule in policy.rules if rule.name == decision.rule)
        assert not deciding.actors


@given(policy=policies(), request=requests())
def test_evaluation_is_deterministic(
    policy: Policy, request: tuple[Principal, str, dict[str, object]]
) -> None:
    """Pure: no I/O, no clock, no hidden state. Cheap to assert and the
    precondition for the simulator and the gateway agreeing."""
    principal, tool, arguments = request

    first = evaluate(policy, principal, tool, arguments)
    second = evaluate(policy, principal, tool, arguments)

    assert first == second


@given(policy=policies(), request=requests(), data=st.data())
def test_narrowing_a_rule_can_only_remove_matches(
    policy: Policy,
    request: tuple[Principal, str, dict[str, object]],
    data: st.DataObject,
) -> None:
    """Monotonicity: making a rule tighter can only ever match less.

    That is what lets an operator reason about "I constrained this rule" without
    re-reading the whole file — and it is why the simulator can report a
    narrowing as strictly-fewer-allows rather than having to diff both
    directions.

    **Narrowing means a subset, and the first version of this test got that
    wrong.** It replaced the rule's tool list with a *different* tool, which is
    swapping one constraint for another, not tightening one — and Hypothesis
    found the case in a few dozen examples: a rule scoped to ``mock-a__search``,
    "narrowed" to ``mock-b__delete_record``, then matched a
    ``mock-b__delete_record`` request it had not matched before. The property was
    wrong, not the evaluator. An unset field accepts everything, so any value
    narrows it; a set field is narrowed only by a subset of itself.
    """
    principal, tool, arguments = request
    if not policy.rules:
        return

    head = policy.rules[0]
    # Unset accepts every tool, so the universe to draw a subset from is the
    # rule's own list when it has one, and all tools when it does not.
    universe = head.tools if head.tools else TOOLS
    chosen = data.draw(st.lists(st.sampled_from(universe), unique=True, min_size=1).map(_freeze))
    narrowed = head.model_copy(update={"tools": chosen})

    before = _matches(head, principal, tool, arguments)
    after = _matches(narrowed, principal, tool, arguments)

    if after:
        assert before, "narrowing made a rule match something it did not before"


# ---------------------------------------------------------------------------
# An independent re-implementation of the match, used as an oracle
# ---------------------------------------------------------------------------


def _matches(rule: Rule, principal: Principal, tool: str, arguments: dict[str, object]) -> bool:
    """Written from ADR 0026's prose rather than from `_rule_matches`.

    Deliberately a second implementation. An oracle that called the function
    under test would agree with it by construction, including when both are
    wrong — the same reason this project does not test a mock against the client
    that generated it.
    """
    actor = principal.actor.subject if principal.actor else None
    if rule.subjects and principal.subject not in rule.subjects:
        return False
    if rule.actors and (actor is None or actor not in rule.actors):
        return False
    if rule.tools and tool not in rule.tools:
        return False
    return all(
        name in arguments and str(arguments[name]) in allowed for name, allowed in rule.args.items()
    )
