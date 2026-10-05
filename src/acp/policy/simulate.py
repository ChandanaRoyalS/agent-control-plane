"""Replay recorded traffic against a proposed policy and report what changes.

The baseline is the recorded decisions (`acp.policy.record`), not the old policy
file. The log holds argument names but not values (ADR 0045), so a call whose
outcome depends on a value is reported `INDETERMINATE` rather than guessed; names
still settle rules on arguments the call never sent (ADR 0031).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum

from acp.policy.evaluate import Decision, Verdict, decision_for, matches_without_arguments
from acp.policy.record import RecordedDecision, Traffic
from acp.policy.schema import RESTRICTIVE, Policy


class Outcome(Enum):
    """What the proposed policy does to one recorded call."""

    UNCHANGED = "unchanged"
    """Same verdict, same rule."""

    NEWLY_DENIED = "newly denied"
    """Was allowed, now refused: a potential outage."""

    NEWLY_ALLOWED = "newly allowed"
    """Was refused, now permitted: the security change a reviewer must check."""

    NEWLY_GATED = "newly needs approval"
    """Was decided outright, now waits for a person (ADR 0048)."""

    SAME_VERDICT_NEW_RULE = "same verdict, different rule"
    """Same verdict, but a different rule now decides (shadowing)."""

    INDETERMINATE = "depends on argument values"
    """Depends on an argument value the log does not carry."""


CHANGED = frozenset(
    {
        Outcome.NEWLY_DENIED,
        Outcome.NEWLY_ALLOWED,
        Outcome.NEWLY_GATED,
        Outcome.INDETERMINATE,
    }
)
"""Outcomes meaning "not proven safe"; includes `INDETERMINATE` deliberately."""


DENY_DEFAULT = "(deny default)"
"""How a decision naming no rule is written in a report."""


def _render(decision: Decision) -> str:
    return f"{decision.verdict.value} by {decision.rule or DENY_DEFAULT}"


@dataclass(frozen=True, slots=True)
class Replay:
    """One recorded call, and what the proposed policy would do with it."""

    recorded: RecordedDecision
    possible: tuple[Decision, ...]
    """Every decision the proposed policy could reach, in policy order; one means settled."""

    outcome: Outcome

    @property
    def certain(self) -> bool:
        return len(self.possible) == 1

    def describe(self) -> str:
        """One line for a report: the call, the change, and the rules involved."""
        was = f"{self.recorded.verdict} by {self.recorded.rule or DENY_DEFAULT}"
        now = " or ".join(_render(decision) for decision in self.possible)
        return f"{self.recorded.describe()}\n      was: {was}\n      now: {now}"


@dataclass(frozen=True, slots=True)
class Simulation:
    """The whole replay: every call, counted, with the interesting ones kept."""

    replays: tuple[Replay, ...]
    traffic: Traffic

    @property
    def counts(self) -> Counter[Outcome]:
        return Counter(replay.outcome for replay in self.replays)

    @property
    def changed(self) -> tuple[Replay, ...]:
        """Everything that is not proven unchanged, in the order it was logged."""
        return tuple(replay for replay in self.replays if replay.outcome in CHANGED)

    @property
    def safe(self) -> bool:
        """True when nothing changed and nothing was left unproven, new allows included."""
        return not self.changed


def possible_decisions(
    policy: Policy,
    subject: str,
    actor: str | None,
    tool: str,
    argument_names: frozenset[str] | None,
) -> tuple[Decision, ...]:
    """Every decision ``policy`` could reach, given arguments nobody recorded.

    The evaluator's first-match walk (ADR 0026) where a rule may possibly match. A
    rule matching on identity and tool either cannot apply (an ``allow`` on an unsent
    argument), definitely applies and stops the walk (no ``args``, or a restriction on
    an unsent argument, ADR 0068), or might apply and is recorded before walking on
    (constrains only sent arguments). The deny default (ADR 0025) ends the walk.
    """
    reachable: list[Decision] = []
    for rule in policy.rules:
        if not matches_without_arguments(rule, subject, actor, tool):
            continue
        if rule.args:
            unsent = argument_names is not None and not set(rule.args).issubset(argument_names)
            if unsent and rule.effect not in RESTRICTIVE:
                continue
            if not unsent:
                reachable.append(decision_for(rule))
                continue
            # A restriction on an unsent argument holds regardless of values.
        reachable.append(decision_for(rule))
        return tuple(reachable)
    reachable.append(Decision(allowed=False, rule=None))
    return tuple(reachable)


_CHANGED_TO = {
    Verdict.ALLOW: Outcome.NEWLY_ALLOWED,
    Verdict.DENY: Outcome.NEWLY_DENIED,
    Verdict.APPROVAL: Outcome.NEWLY_GATED,
}


def classify(recorded: RecordedDecision, possible: tuple[Decision, ...]) -> Outcome:
    """Return the call's outcome; indeterminate only if the possible verdicts differ."""
    verdicts = {decision.verdict for decision in possible}
    if len(verdicts) > 1:
        return Outcome.INDETERMINATE

    verdict = next(iter(verdicts))
    if verdict is not recorded.verdict:
        return _CHANGED_TO[verdict]
    if all(decision.rule == recorded.rule for decision in possible):
        return Outcome.UNCHANGED
    return Outcome.SAME_VERDICT_NEW_RULE


def simulate(policy: Policy, traffic: Traffic) -> Simulation:
    """Replay every recorded decision against ``policy``.

    Pure; shares `matches_without_arguments` with the live path so it cannot drift
    (ADR 0030).
    """
    replays: list[Replay] = []
    for recorded in traffic.decisions:
        possible = possible_decisions(
            policy,
            recorded.subject,
            recorded.actor,
            recorded.tool,
            recorded.argument_names,
        )
        replays.append(
            Replay(recorded=recorded, possible=possible, outcome=classify(recorded, possible))
        )
    return Simulation(replays=tuple(replays), traffic=traffic)
