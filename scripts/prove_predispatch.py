#!/usr/bin/env python3
"""Prove the pre-dispatch check never refuses a call the real evaluator allows.

    uv run python scripts/prove_predispatch.py

The pre-dispatch layer (ADR 0043) refuses a call before anything parses a body.
Its one obligation is negative: **it may refuse, and it may never refuse
something `enforce_call` would have permitted.** A false refusal there is a
legitimate caller broken by an optimisation that was supposed to be invisible —
intermittent, dependent on the shape of the policy rather than the request, and
indistinguishable to whoever hits it from a policy bug.

That obligation is not the kind a test asserts once. So this script does two
things, and it needs both:

**Part 1 — search for a counterexample.** Generate policies, ask the pre-check
about every request, and for every call it would refuse, re-run the *real*
evaluator against every argument mapping a caller could send. Any allow is a
false refusal, printed with the policy that produced it.

**Part 2 — check the search has teeth.** A search that finds nothing proves
nothing unless it would have found something. So the same search is re-run
against deliberately broken readings of `could_ever_allow`, and each one must be
caught. The first is the trap the real implementation exists to avoid.

**Part 3 — the two header bugs, against the test suite.** `_declared_tool` has
its own false-refusal modes, and they are not visible to a search over policies
because they are about what the headers *mean*. Those are mutated in the source
and the unit suite is required to notice, using the same machinery as
`mutate_result_cache.py` — one implementation of the dangerous in-place edit.
"""

from __future__ import annotations

import itertools
import random
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

from mutate_no_passthrough import Mutation, apply, failing_tests, working_tree_is_clean

from acp.identity.principal import Actor, Principal
from acp.policy.evaluate import evaluate, matches_without_arguments
from acp.policy.predispatch import could_ever_allow
from acp.policy.schema import Effect, Policy, Rule

# ---------------------------------------------------------------------------
# The alphabets
# ---------------------------------------------------------------------------

# Deliberately tiny, for the reason the property tests give: with free text the
# rules would never fire and every request would fall through to the deny
# default, testing one branch very thoroughly and nothing else.
SUBJECTS: tuple[str, ...] = ("alice", "bob")
ACTORS: tuple[str | None, ...] = (None, "agent-a")
TOOLS: tuple[str, ...] = ("mock-a__search", "mock-b__delete_record")
ARG_VALUES: tuple[str, ...] = ("public", "secret")

# Every mapping a caller could send, including the two that match no rule: the
# empty one (the call omits the argument) and an unlisted value.
MAPPINGS: tuple[dict[str, object], ...] = (
    {},
    {"doc_id": "public"},
    {"doc_id": "secret"},
    {"doc_id": "unlisted"},
)

SEED = 20260812
POLICIES = 30_000
MAX_RULES = 4


def _subsets(values: Sequence[str]) -> list[tuple[str, ...]]:
    """Every selection including the empty one, which means "matches anything"
    and is the case most likely to interact badly with the others."""
    return [
        tuple(chosen)
        for size in range(len(values) + 1)
        for chosen in itertools.combinations(values, size)
    ]


def _rule_shapes() -> list[tuple[Effect, tuple[str, ...], tuple[str, ...], tuple[str, ...], dict]]:
    arg_shapes: list[dict[str, tuple[str, ...]]] = [{}]
    arg_shapes += [{"doc_id": values} for values in _subsets(ARG_VALUES) if values]
    return [
        (effect, subjects, actors, tools, args)
        for effect in (Effect.ALLOW, Effect.DENY)
        for subjects in _subsets(SUBJECTS)
        for actors in _subsets(("agent-a",))
        for tools in _subsets(TOOLS)
        for args in arg_shapes
    ]


def _requests() -> list[tuple[Principal, str]]:
    return [
        (
            Principal(
                subject=subject,
                issuer="https://idp.test",
                actor=Actor(subject=actor) if actor is not None else None,
            ),
            tool,
        )
        for subject in SUBJECTS
        for actor in ACTORS
        for tool in TOOLS
    ]


def _policies(rng: random.Random, shapes: Sequence[tuple]) -> Iterator[Policy]:
    for _ in range(POLICIES):
        count = rng.randint(0, MAX_RULES)
        yield Policy(
            rules=tuple(
                Rule(
                    name=f"r{index}",
                    effect=effect,
                    subjects=subjects,
                    actors=actors,
                    tools=tools,
                    args=args,
                )
                for index, (effect, subjects, actors, tools, args) in enumerate(
                    rng.choice(shapes) for _ in range(count)
                )
            )
        )


# ---------------------------------------------------------------------------
# Part 1 and 2 — the counterexample search
# ---------------------------------------------------------------------------

Reading = Callable[[Policy, Principal, str], bool]


def search(reading: Reading, *, stop_at: int = 3) -> tuple[int, int, list[str]]:
    """Re-check everything ``reading`` would refuse against the real evaluator.

    Returns how many calls it refused, how many re-checks that took, and the
    first few counterexamples — a refusal the evaluator disagrees with.
    """
    # Seeded and reproducible: a counterexample found here must be findable
    # again. Nothing cryptographic depends on it.
    rng = random.Random(SEED)  # noqa: S311
    shapes = _rule_shapes()
    requests = _requests()
    refused = 0
    rechecks = 0
    counterexamples: list[str] = []

    for policy in _policies(rng, shapes):
        for principal, tool in requests:
            if reading(policy, principal, tool):
                continue
            refused += 1
            for arguments in MAPPINGS:
                rechecks += 1
                decision = evaluate(policy, principal, tool, arguments)
                if decision.allowed and len(counterexamples) < stop_at:
                    rules = ", ".join(
                        f"{rule.name}:{rule.effect.value}"
                        f"{'/args' if rule.args else ''}"
                        f"{'/tools' if rule.tools else ''}"
                        for rule in policy.rules
                    )
                    counterexamples.append(
                        f"{principal.subject} -> {tool} {arguments} "
                        f"refused, but rule {decision.rule!r} allows it [{rules}]"
                    )
    return refused, rechecks, counterexamples


def naive_empty_arguments(policy: Policy, principal: Principal, tool: str) -> bool:
    """**The trap.** Ask the real evaluator with no arguments.

    The obvious implementation, and wrong: a rule constraining an argument
    cannot match an empty mapping, so every call permitted by an
    argument-scoped allow is refused.
    """
    return evaluate(policy, principal, tool, {}).allowed


def deny_wins_anywhere(policy: Policy, principal: Principal, tool: str) -> bool:
    """Refuse if *any* matching deny exists, wherever it sits.

    Plausible if you think of a deny as absolute — and it is the design ADR 0026
    rejected. It refuses calls a later allow permits.
    """
    actor = principal.actor.subject if principal.actor else None
    for rule in policy.rules:
        if matches_without_arguments(rule, principal.subject, actor, tool) and (
            rule.effect is Effect.DENY
        ):
            return False
    return could_ever_allow(policy, principal, tool)


def argument_denies_settle_it(policy: Policy, principal: Principal, tool: str) -> bool:
    """Let an argument-constrained deny decide the whole tool.

    One character away from the real thing — drop the `if not rule.args` guard —
    and it refuses every call to a tool that has any deny mentioning it, including
    the calls whose arguments that deny does not cover.
    """
    actor = principal.actor.subject if principal.actor else None
    for rule in policy.rules:
        if not matches_without_arguments(rule, principal.subject, actor, tool):
            continue
        return rule.effect is Effect.ALLOW
    return False


BROKEN_READINGS: tuple[tuple[str, Reading], ...] = (
    ("evaluate with an empty argument mapping", naive_empty_arguments),
    ("let a deny anywhere in the file win", deny_wins_anywhere),
    ("let an argument-scoped deny settle the whole tool", argument_denies_settle_it),
)


# ---------------------------------------------------------------------------
# Part 3 — the header readings, mutated in source
# ---------------------------------------------------------------------------

PREDISPATCH = "src/acp/policy/predispatch.py"
SUITE = "tests/unit/policy/test_predispatch.py"

MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="decide every name-bearing method, not only tools/call",
        path=PREDISPATCH,
        anchor="    if method != TOOL_CALL_METHOD or method not in NAME_BEARING_METHODS:",
        replacement="    if method is None or method not in NAME_BEARING_METHODS:",
        # A `resources/read` URI checked against tool rules matches none of them,
        # falls to the deny default, and refuses a request the real check allows.
        caught_by=frozenset({"test_a_method_whose_name_is_not_a_tool_is_not_decided"}),
        suite=SUITE,
    ),
    Mutation(
        name="match the raw header instead of decoding it",
        path=PREDISPATCH,
        anchor="    return decode_header_value(name) or None",
        replacement="    return name or None",
        # The base64 sentinel matches no rule, so a tool with a non-ASCII name
        # becomes uncallable. The refusal-side test is listed too: together the
        # pair rules out "decode" *and* "decline on anything encoded".
        caught_by=frozenset({"test_an_encoded_name_is_decoded_before_it_is_matched"}),
        suite=SUITE,
    ),
)


# ---------------------------------------------------------------------------


def main() -> int:
    print("Part 1 — searching for a call the pre-check refuses and the evaluator allows.\n")
    refused, rechecks, counterexamples = search(could_ever_allow)
    print(f"  policies sampled:        {POLICIES:,}")
    print(f"  calls the pre-check refused: {refused:,}")
    print(f"  argument mappings re-checked: {rechecks:,}")
    if counterexamples:
        print("\n  FALSE REFUSALS FOUND:")
        for line in counterexamples:
            print(f"    {line}")
        print("\nThe pre-dispatch check is refusing legitimate traffic. Do not ship it.")
        return 1
    print("  false refusals:          0\n")

    print("Part 2 — checking the search would have found one.\n")
    blind: list[str] = []
    for name, reading in BROKEN_READINGS:
        _, _, found = search(reading, stop_at=1)
        if found:
            print(f"  caught   {name}")
            print(f"           e.g. {found[0]}")
        else:
            blind.append(name)
            print(f"  MISSED   {name}")
    if blind:
        print(f"\nFAILED: the search is blind to {len(blind)} broken reading(s).")
        print("Part 1's clean result means nothing until this passes.")
        return 1
    print()

    print("Part 3 — breaking the header reading on purpose.\n")
    if not working_tree_is_clean():
        print(
            "  skipped: this part edits source in place and needs a clean tree,\n"
            "  which is what makes `git checkout .` a complete recovery.",
            file=sys.stderr,
        )
        return 1

    survivors: list[str] = []
    root = Path(__file__).resolve().parents[1]
    for mutation in MUTATIONS:
        path = root / mutation.path
        original = apply(mutation)
        try:
            failed = failing_tests(mutation.suite)
        finally:
            path.write_text(original, encoding="utf-8")

        if mutation.caught_by <= failed:
            extra = failed - mutation.caught_by
            note = f" (also: {', '.join(sorted(extra))})" if extra else ""
            print(f"  caught   {mutation.name}{note}")
        else:
            survivors.append(mutation.name)
            missed = ", ".join(sorted(mutation.caught_by - failed)) or "nothing failed"
            print(f"  SURVIVED {mutation.name} — expected to fail: {missed}")

    print()
    if survivors:
        print(f"FAILED: {len(survivors)} mutation(s) survived — {'; '.join(survivors)}")
        return 1

    print(
        f"SAFE: {rechecks:,} re-checks with no false refusal, a search that catches "
        f"{len(BROKEN_READINGS)} broken readings, and {len(MUTATIONS)} header bugs "
        "caught by the tests meant to catch them."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
