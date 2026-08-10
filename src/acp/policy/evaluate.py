"""Evaluate a request against a policy: allow or deny, and why.

Task 33 is the evaluator — a pure function over a loaded policy (task 32) and the
identity of a request. It decides; it does not enforce. Wiring this into the
request path so a denied call is actually refused is task 34, and keeping the two
apart means the decision logic is testable without a running gateway, the same
split identity used between building a Principal and trusting one.

The rules, spelled out because everything downstream assumes them:

- **Deny by default.** A request matching no rule is denied. This is not a rule
  in the file; it is the absence of one, and it is why an empty policy denies
  everything (ADR 0025).
- **First match wins.** Rules are evaluated in document order and the first whose
  match fields all hold decides the outcome — allow or deny. This is what lets a
  narrow deny sit ahead of a broad allow.
- **A field matches by membership; unset matches anything.** A rule's `subjects`,
  `actors`, or `tools` set to a list matches when the request's value is in it;
  left empty, it matches any value. All set fields must hold — they are ANDed.
- **A named `actors` requires an actor.** A rule that lists actors cannot match a
  request with no actor at all: `None` is in no list. "Unset means any" and "set
  means one of these" are different claims, and a non-delegated request satisfies
  the first but not the second.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from acp.identity.principal import Principal
from acp.policy.schema import Effect, Policy, Rule


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of evaluating one request against a policy.

    Carries the rule that decided it, or ``None`` when nothing matched and the
    deny default applied. The name is what the audit log (a later task) records: a
    decision nobody can attribute to a rule is a decision nobody can explain.
    """

    allowed: bool
    rule: str | None
    """The name of the rule that decided this, or ``None`` for the deny default.

    ``rule is None`` and ``allowed is True`` never occur together: the default is
    always a denial, so an allow always names the rule that granted it.
    """

    @property
    def reason(self) -> str:
        """A short human-readable account, for logs and error messages."""
        if self.rule is None:
            return "denied by default (no rule matched)"
        verb = "allowed" if self.allowed else "denied"
        return f"{verb} by rule {self.rule!r}"


def _rule_matches(
    rule: Rule,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, object],
) -> bool:
    """Does this rule's match section hold for the request?

    Every set field must match; an unset field (empty tuple, or empty ``args``)
    matches anything. A rule that names actors cannot match a request whose actor
    is ``None``. A rule that constrains an argument cannot match a call that omits
    that argument or supplies a value outside the allowed set — the same "set
    means one of these" claim as the other fields, so a missing argument is not a
    match any more than a missing actor is.
    """
    if rule.subjects and subject not in rule.subjects:
        return False
    if rule.actors and (actor is None or actor not in rule.actors):
        return False
    if rule.tools and tool not in rule.tools:
        return False
    for name, allowed in rule.args.items():
        if name not in arguments:
            return False
        # Compare as a string: policy values are strings (YAML scalars), and a
        # tool argument's JSON value may be a number or bool. Matching by string
        # form keeps the exact-match model simple and predictable across types.
        if str(arguments[name]) not in allowed:
            return False
    return True


def evaluate(
    policy: Policy,
    principal: Principal,
    tool: str,
    arguments: Mapping[str, object] | None = None,
) -> Decision:
    """Decide whether ``principal`` may call ``tool`` under ``policy``.

    Pure: no I/O, no clock, no dependence on anything but its arguments. The
    tool is the qualified name (``upstream__tool``, ADR 0003), matched verbatim.

    ``arguments`` is the call's argument mapping, used by rules that constrain
    arguments. It defaults to empty, which is correct for the two callers that
    have no arguments to offer: ``tools/list`` filtering, where the call has not
    happened yet, and any check that only asks "could this tool ever be called".
    A rule that constrains an argument simply cannot match an empty mapping, so
    an argument-scoped allow does not grant list visibility on its own — the
    coarse tool-level rules decide what is visible, the argument check decides
    what is callable.
    """
    args = arguments if arguments is not None else {}
    actor = principal.actor.subject if principal.actor else None
    for rule in policy.rules:
        if _rule_matches(rule, principal.subject, actor, tool, args):
            return Decision(allowed=rule.effect is Effect.ALLOW, rule=rule.name)
    return Decision(allowed=False, rule=None)
