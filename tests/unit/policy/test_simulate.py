"""Replaying recorded traffic against a proposed policy.

Two things are being asserted, and the second is the harder one.

The first is the diff itself: five outcomes, not two, because "how many allows
and how many denies" hides a policy edit that reached the same verdict through a
rule nobody meant to write.

The second is the *uncertainty*. The log carries argument names and never
argument values (ADR 0045), so a rule constraining an argument may or may not
have fired on a recorded call. The tests below pin both directions: what the
simulator must refuse to guess, and — the part that makes it useful rather than
merely honest — what it can still settle from names alone.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator

from acp.identity.principal import Principal
from acp.policy.evaluate import evaluate
from acp.policy.record import RecordedDecision, Traffic
from acp.policy.schema import Effect, Policy, Rule
from acp.policy.simulate import Outcome, classify, possible_decisions, simulate

TOOL = "mock-a__search"


def recorded(
    *,
    subject: str = "alice",
    actor: str | None = None,
    tool: str = TOOL,
    allowed: bool = True,
    rule: str | None = "allow-search",
    argument_names: frozenset[str] | None = frozenset(),
) -> RecordedDecision:
    return RecordedDecision(
        subject=subject,
        actor=actor,
        tool=tool,
        allowed=allowed,
        rule=rule,
        argument_names=argument_names,
    )


def principal_of(subject: str = "alice") -> Principal:
    return Principal(subject=subject, issuer="urn:acp:test")


def traffic_of(*decisions: RecordedDecision) -> Traffic:
    return Traffic(decisions=decisions, unreadable=0, other_events=0)


ALLOW_SEARCH = Rule(name="allow-search", effect=Effect.ALLOW, tools=(TOOL,))
DENY_SEARCH = Rule(name="deny-search", effect=Effect.DENY, tools=(TOOL,))


# ---------------------------------------------------------------------------
# possible_decisions — the walk, with a third state
# ---------------------------------------------------------------------------


def test_a_rule_with_no_argument_constraints_settles_the_call() -> None:
    possible = possible_decisions(Policy(rules=(ALLOW_SEARCH,)), "alice", None, TOOL, frozenset())

    assert len(possible) == 1
    assert possible[0].rule == "allow-search"


def test_nothing_matching_is_the_deny_default() -> None:
    possible = possible_decisions(
        Policy(rules=(ALLOW_SEARCH,)), "alice", None, "other", frozenset()
    )

    assert len(possible) == 1
    assert not possible[0].allowed
    assert possible[0].rule is None


def test_a_rule_after_a_definite_match_is_unreachable() -> None:
    """First match wins (ADR 0026), so the walk stops. A simulator that listed
    every matching rule as a possibility would report uncertainty that the
    evaluator does not have."""
    policy = Policy(rules=(ALLOW_SEARCH, DENY_SEARCH))

    possible = possible_decisions(policy, "alice", None, TOOL, frozenset())

    assert len(possible) == 1
    assert possible[0].rule == "allow-search"


def test_a_rule_constraining_an_argument_the_call_sent_is_only_a_possibility() -> None:
    """The uncertainty the log cannot remove: `doc_id` was sent, but its value
    is not recorded, so whether this rule fired depends on data nobody has."""
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            ALLOW_SEARCH,
        )
    )

    possible = possible_decisions(policy, "alice", None, TOOL, frozenset({"doc_id"}))

    assert [decision.rule for decision in possible] == ["deny-secret", "allow-search"]


def test_a_rule_constraining_an_argument_the_call_never_sent_cannot_have_fired() -> None:
    """**The reason the log records argument names at all.**

    A missing argument is not a match (ADR 0031), so this is certainty rather
    than an assumption — a definite answer recovered from a field that records
    nothing sensitive. Without it this call would be reported as indeterminate
    and a reviewer would have to check it by hand.
    """
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            ALLOW_SEARCH,
        )
    )

    possible = possible_decisions(policy, "alice", None, TOOL, frozenset({"query"}))

    assert len(possible) == 1
    assert possible[0].rule == "allow-search"


def test_an_unknown_argument_set_cannot_rule_anything_out() -> None:
    """A record predating the field. The same policy and the same call as the
    test above, and the answer is uncertain again — which is why `None` and
    `frozenset()` are kept apart rather than collapsed."""
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            ALLOW_SEARCH,
        )
    )

    possible = possible_decisions(policy, "alice", None, TOOL, None)

    assert len(possible) == 2


def test_rules_for_other_principals_are_not_possibilities() -> None:
    policy = Policy(rules=(Rule(name="bob-only", effect=Effect.DENY, subjects=("bob",)),))

    possible = possible_decisions(policy, "alice", None, TOOL, frozenset())

    assert possible[0].rule is None


# ---------------------------------------------------------------------------
# classify — the five outcomes
# ---------------------------------------------------------------------------


def test_same_verdict_same_rule_is_unchanged() -> None:
    policy = Policy(rules=(ALLOW_SEARCH,))
    call = recorded(allowed=True, rule="allow-search")

    assert classify(call, possible_decisions(policy, "alice", None, TOOL, frozenset())) is (
        Outcome.UNCHANGED
    )


def test_an_allow_that_becomes_a_deny_is_the_outage() -> None:
    policy = Policy(rules=(DENY_SEARCH,))
    call = recorded(allowed=True, rule="allow-search")

    assert classify(call, possible_decisions(policy, "alice", None, TOOL, frozenset())) is (
        Outcome.NEWLY_DENIED
    )


def test_a_deny_that_becomes_an_allow_is_the_security_change() -> None:
    policy = Policy(rules=(ALLOW_SEARCH,))
    call = recorded(allowed=False, rule=None)

    assert classify(call, possible_decisions(policy, "alice", None, TOOL, frozenset())) is (
        Outcome.NEWLY_ALLOWED
    )


def test_the_same_verdict_from_a_different_rule_is_reported_not_hidden() -> None:
    """Not a functional change, and not noise: a rule somebody just wrote is now
    shadowing the one that used to decide this call. They agree today, and the
    next edit to either is where they stop agreeing."""
    policy = Policy(rules=(Rule(name="allow-everything", effect=Effect.ALLOW),))
    call = recorded(allowed=True, rule="allow-search")

    assert classify(call, possible_decisions(policy, "alice", None, TOOL, frozenset())) is (
        Outcome.SAME_VERDICT_NEW_RULE
    )


def test_possibilities_that_disagree_are_indeterminate() -> None:
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            ALLOW_SEARCH,
        )
    )
    call = recorded(allowed=True, rule="allow-search", argument_names=frozenset({"doc_id"}))

    assert classify(
        call, possible_decisions(policy, "alice", None, TOOL, frozenset({"doc_id"}))
    ) is (Outcome.INDETERMINATE)


def test_possibilities_that_agree_on_the_verdict_are_not_indeterminate() -> None:
    """**Uncertainty is settled by the verdicts, not by the count.**

    Two rules could each decide this call and both deny it. Nothing is uncertain
    about whether the caller gets in — only about which rule stopped them, and a
    policy edit is reviewed on the first question. Reporting it as indeterminate
    would bury the real changes under noise nobody can act on.
    """
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            DENY_SEARCH,
        )
    )
    call = recorded(allowed=True, rule="allow-search", argument_names=frozenset({"doc_id"}))

    outcome = classify(call, possible_decisions(policy, "alice", None, TOOL, frozenset({"doc_id"})))

    assert outcome is Outcome.NEWLY_DENIED


# ---------------------------------------------------------------------------
# simulate — the whole replay
# ---------------------------------------------------------------------------


def test_an_unchanged_policy_is_safe() -> None:
    policy = Policy(rules=(ALLOW_SEARCH,))
    simulation = simulate(policy, traffic_of(recorded(), recorded(), recorded()))

    assert simulation.safe
    assert simulation.counts[Outcome.UNCHANGED] == 3
    assert simulation.changed == ()


def test_a_tightened_policy_reports_every_call_it_would_break() -> None:
    policy = Policy(rules=(DENY_SEARCH,))
    simulation = simulate(policy, traffic_of(recorded(), recorded(subject="bob")))

    assert not simulation.safe
    assert len(simulation.changed) == 2
    assert all(replay.outcome is Outcome.NEWLY_DENIED for replay in simulation.changed)


def test_indeterminate_counts_as_not_proven_safe() -> None:
    """The deliberate call. Unproven is not unchanged, and a gate that treats
    "I could not tell" as "fine" passes the one case somebody needed to look
    at."""
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            ALLOW_SEARCH,
        )
    )
    simulation = simulate(policy, traffic_of(recorded(argument_names=frozenset({"doc_id"}))))

    assert not simulation.safe
    assert simulation.counts[Outcome.INDETERMINATE] == 1


def test_the_changed_list_keeps_the_order_the_calls_were_logged_in() -> None:
    """A report a human reads in the order the traffic happened, so "it started
    failing after 14:03" is answerable from it."""
    policy = Policy(rules=(DENY_SEARCH,))
    simulation = simulate(
        policy,
        traffic_of(
            recorded(subject="first"),
            recorded(subject="second"),
            recorded(subject="third"),
        ),
    )

    assert [replay.recorded.subject for replay in simulation.changed] == [
        "first",
        "second",
        "third",
    ]


def test_the_replay_keeps_the_traffic_it_was_built_from() -> None:
    """Including the unreadable count, so a report can say how much of the log
    it actually read. "No changes" over a log that failed to parse is the
    reassuring lie this exists to prevent."""
    traffic = Traffic(decisions=(recorded(),), unreadable=17, other_events=3)

    simulation = simulate(Policy(rules=(ALLOW_SEARCH,)), traffic)

    assert simulation.traffic.unreadable == 17
    assert simulation.traffic.total == 21


def test_an_empty_log_produces_an_empty_simulation() -> None:
    simulation = simulate(Policy(rules=(ALLOW_SEARCH,)), traffic_of())

    assert simulation.replays == ()
    assert simulation.safe


# ---------------------------------------------------------------------------
# The report line
# ---------------------------------------------------------------------------


def test_a_change_describes_both_sides() -> None:
    policy = Policy(rules=(DENY_SEARCH,))
    simulation = simulate(policy, traffic_of(recorded(actor="agent-a")))

    described = simulation.changed[0].describe()

    assert "alice+agent-a" in described
    assert "was: allow by allow-search" in described
    assert "now: deny by deny-search" in described


def test_an_indeterminate_change_names_both_possibilities() -> None:
    policy = Policy(
        rules=(
            Rule(
                name="deny-secret", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}
            ),
            ALLOW_SEARCH,
        )
    )
    simulation = simulate(policy, traffic_of(recorded(argument_names=frozenset({"doc_id"}))))

    described = simulation.changed[0].describe()

    assert "deny by deny-secret or allow by allow-search" in described
    assert "(doc_id)" in described


def test_the_deny_default_is_written_as_words_not_as_none() -> None:
    policy = Policy(rules=())
    simulation = simulate(policy, traffic_of(recorded()))

    assert "(deny default)" in simulation.changed[0].describe()
    assert "None" not in simulation.changed[0].describe()


# ---------------------------------------------------------------------------
# The invariant the whole report rests on, by exhaustive enumeration
# ---------------------------------------------------------------------------


def _rule_pool() -> list[Rule]:
    """Every shape a rule can take over a two-tool, one-argument world."""
    tool_sets: list[tuple[str, ...]] = [(), (TOOL,), ("t2",), (TOOL, "t2")]
    arg_shapes: list[dict[str, tuple[str, ...]]] = [
        {},
        {"doc_id": ("public",)},
        {"doc_id": ("public", "secret")},
    ]
    return [
        Rule(name="placeholder", effect=effect, tools=tools, args=args)
        for effect in (Effect.ALLOW, Effect.DENY)
        for tools in tool_sets
        for args in arg_shapes
    ]


def _policies(pool: list[Rule], depth: int = 2) -> Iterator[Policy]:
    """Every policy up to ``depth`` rules, names made unique by position."""
    for length in range(depth + 1):
        for combination in itertools.product(pool, repeat=length):
            yield Policy(
                rules=tuple(
                    rule.model_copy(update={"name": f"r{index}"})
                    for index, rule in enumerate(combination)
                )
            )


# What a caller could have sent, given what the log says the argument names were.
MAPPINGS: dict[frozenset[str], tuple[dict[str, object], ...]] = {
    frozenset(): ({},),
    frozenset({"doc_id"}): (
        {"doc_id": "public"},
        {"doc_id": "secret"},
        {"doc_id": "unlisted"},
    ),
}


def test_the_true_decision_is_always_among_the_possibilities() -> None:
    """**Soundness.** Whatever the call really sent, the answer is in the list.

    Everything the report says rests on this. If the real decision could fall
    outside the possibilities, then an `UNCHANGED` verdict would be a claim
    about calls the simulator never considered — and the one number a reviewer
    trusts would be the one that is wrong.

    Checked by enumeration rather than by argument: every policy of up to two
    rules over a two-tool, one-argument world, against every argument mapping a
    caller could have sent.
    """
    checked = 0
    for policy in _policies(_rule_pool()):
        for tool in (TOOL, "t2"):
            for names, mappings in MAPPINGS.items():
                possible = possible_decisions(policy, "alice", None, tool, names)
                for arguments in mappings:
                    checked += 1
                    assert evaluate(policy, principal_of(), tool, arguments) in possible

    assert checked == 4_808, "the enumeration changed size; it is no longer the proof it was"


def test_a_single_possibility_is_a_promise_not_a_guess() -> None:
    """**Completeness.** One possibility means the answer cannot be anything else.

    The other half, and the one that makes the report actionable: a call the
    simulator reports as settled must be settled for *every* argument value the
    log leaves unrecorded. Without this, `possible_decisions` could return one
    answer by simply forgetting a rule, and every `UNCHANGED` would be a
    coin-flip that happened to land right.
    """
    for policy in _policies(_rule_pool()):
        for tool in (TOOL, "t2"):
            for names, mappings in MAPPINGS.items():
                possible = possible_decisions(policy, "alice", None, tool, names)
                if len(possible) != 1:
                    continue
                for arguments in mappings:
                    assert evaluate(policy, principal_of(), tool, arguments) == possible[0]
