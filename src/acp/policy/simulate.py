"""Replay recorded traffic against a proposed policy and report what changes.

The question this answers is the one that stops people editing a policy at all:
*if I merge this, what breaks?* Without an answer, every edit is either shipped
on faith or padded with allows until nothing can fail — and a policy nobody
dares tighten is a policy that only ever gets looser. So this takes the
decisions the gateway actually made (`acp.policy.record`), asks a proposed
policy the same questions, and prints the difference.

**The recorded log is the baseline, not the old policy file.** What the gateway
*did* is a fact; what a policy file says it would have done is a re-derivation
that can be wrong — the file may have changed since, or never have been the one
that was loaded. Diffing against the record also means the old policy need not
still exist, which is exactly the situation somebody investigating a change is
usually in.

**And the honest part: the log does not carry argument values, on purpose.**
Argument values are user data (ADR 0045); the log carries argument *names*. So a
rule constraining an argument may or may not have fired on a recorded call, and
no amount of analysis here can settle it. Rather than guess — in either
direction — this reports such calls as `INDETERMINATE` and says how many. A
simulator that quietly assumed "the argument probably matched" would produce a
clean report and a broken deployment, which is the failure this whole tool
exists to prevent.

What the names *do* buy is that many of those calls stop being indeterminate: a
rule constraining `doc_id` cannot have fired on a call that sent no `doc_id`,
because a missing argument is not a match (ADR 0031). That is a definite answer
recovered from a field that records nothing sensitive.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum

from acp.policy.evaluate import Decision, matches_without_arguments
from acp.policy.record import RecordedDecision, Traffic
from acp.policy.schema import Effect, Policy


class Outcome(Enum):
    """What the proposed policy does to one recorded call.

    Five, not two, and the extra three are the ones worth reading. "How many
    allows and how many denies" is a report that hides a policy edit which
    reached the same verdict through a rule nobody meant to write.
    """

    UNCHANGED = "unchanged"
    """Same verdict, same rule. The bulk of any healthy diff."""

    NEWLY_DENIED = "newly denied"
    """Was allowed, is now refused. **The outage.** Read this list first."""

    NEWLY_ALLOWED = "newly allowed"
    """Was refused, is now permitted. **The security change.** Intended or not,
    it is the half of the diff a reviewer is accountable for."""

    SAME_VERDICT_NEW_RULE = "same verdict, different rule"
    """The right answer for a different reason.

    Not a functional change, and not noise either: it means a rule somebody just
    wrote is now shadowing one that used to decide this call. The verdicts agree
    *today*, and the next edit to either rule is where they stop agreeing.
    """

    INDETERMINATE = "depends on argument values"
    """Cannot be settled from the record, because a rule constrains an argument
    whose value the log deliberately does not carry."""


CHANGED = frozenset({Outcome.NEWLY_DENIED, Outcome.NEWLY_ALLOWED, Outcome.INDETERMINATE})
"""Outcomes that mean "this edit is not proven safe".

`INDETERMINATE` is in here, and that is the deliberate call: unproven is not the
same as unchanged, and a gate that treats "I could not tell" as "fine" is a gate
that passes the one case somebody needed to look at.
"""


DENY_DEFAULT = "(deny default)"
"""How a decision naming no rule is written in a report.

Named rather than repeated, because "no rule matched" and "a rule called None"
are the same six characters on a terminal and very different things to read.
"""


def _render(decision: Decision) -> str:
    return f"{'allow' if decision.allowed else 'deny'} by {decision.rule or DENY_DEFAULT}"


@dataclass(frozen=True, slots=True)
class Replay:
    """One recorded call, and what the proposed policy would do with it."""

    recorded: RecordedDecision
    possible: tuple[Decision, ...]
    """Every decision the proposed policy could reach for this call.

    One element means the answer is settled. More than one means the walk
    reached a rule that constrains an argument, and which of them applies
    depends on a value the log does not carry — listed in policy order, so the
    first is what happens if that rule matches and the rest are what happens if
    it does not.
    """

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
        """True when nothing changed and nothing was left unproven.

        Deliberately not "no denials appeared". A policy edit that only ever
        *adds* permissions is not safe by default; it is the other half of the
        review.
        """
        return not self.changed


def possible_decisions(
    policy: Policy,
    subject: str,
    actor: str | None,
    tool: str,
    argument_names: frozenset[str] | None,
) -> tuple[Decision, ...]:
    """Every decision ``policy`` could reach, given arguments nobody recorded.

    The evaluator's walk (first match wins, ADR 0026) with one extra state: a
    rule may *possibly* match. Walking in policy order, each rule is one of
    three things.

    - **Cannot apply.** Its identity or tool section does not hold, or it
      constrains an argument the call never sent — and a missing argument is not
      a match (ADR 0031), so this is a definite "no", not an uncertainty. Skip
      it. Recovering these is the entire reason the log records argument names.
    - **Definitely applies.** It matches on identity and tool and constrains no
      arguments. It decides the call; nothing after it can be reached. Record it
      and stop.
    - **Might apply.** It matches on identity and tool and constrains only
      arguments the call did send. Whether it fires depends on values the log
      does not carry. Record it as one possibility and keep walking, because the
      other possibility is that it did not fire and a later rule decided.

    Falling off the end is the deny default (ADR 0025), which is itself a
    possibility and is appended as one.

    A single-element result is a settled answer. The order is meaningful: policy
    order, so the reader can see which rule the uncertainty came from.
    """
    reachable: list[Decision] = []
    for rule in policy.rules:
        if not matches_without_arguments(rule, subject, actor, tool):
            continue
        if rule.args:
            if argument_names is not None and not set(rule.args).issubset(argument_names):
                # Constrains something this call did not send. It cannot have
                # fired, and that is certainty rather than an assumption.
                continue
            reachable.append(Decision(allowed=rule.effect is Effect.ALLOW, rule=rule.name))
            continue
        reachable.append(Decision(allowed=rule.effect is Effect.ALLOW, rule=rule.name))
        return tuple(reachable)
    reachable.append(Decision(allowed=False, rule=None))
    return tuple(reachable)


def classify(recorded: RecordedDecision, possible: tuple[Decision, ...]) -> Outcome:
    """Which of the five outcomes this call falls into.

    The uncertain case is settled first and it is settled *by the verdicts, not
    by the count of possibilities*. Three rules that could each decide a call
    but all deny it leave nothing uncertain about whether the caller gets in —
    only about which rule stopped them, and a policy edit is reviewed on the
    first question. Reporting it as indeterminate would bury a real change under
    noise nobody can act on.
    """
    verdicts = {decision.allowed for decision in possible}
    if len(verdicts) > 1:
        return Outcome.INDETERMINATE

    allowed = next(iter(verdicts))
    if allowed != recorded.allowed:
        return Outcome.NEWLY_ALLOWED if allowed else Outcome.NEWLY_DENIED
    if all(decision.rule == recorded.rule for decision in possible):
        return Outcome.UNCHANGED
    return Outcome.SAME_VERDICT_NEW_RULE


def simulate(policy: Policy, traffic: Traffic) -> Simulation:
    """Replay every recorded decision against ``policy``.

    Pure, like the evaluator it is built on: no clock, no I/O, no gateway. The
    same `matches_without_arguments` the live path uses, so the simulator cannot
    drift from the thing it simulates — which is the property that makes its
    answer worth anything (ADR 0030).
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
