"""Evaluate a request against a policy: allow or deny, and why.

Pure decision logic; ``acp.policy.enforce`` does the refusing. The rules:

- Deny by default: a request matching no rule is denied, so an empty policy denies
  everything (ADR 0025).
- First match wins: rules run in document order and the first whose set fields all
  hold decides (ADR 0026).
- ``subjects``, ``actors`` and ``tools`` match by membership; empty matches anything.
  A rule naming actors never matches a request with no actor.
- Arguments fail closed per effect (ADR 0068): an ``allow`` needs the argument as a
  scalar whose canonical form is exactly in the set; a ``deny`` or
  ``require_approval`` is cleared only by a scalar whose folded form is outside the
  set, so a missing, non-scalar or re-spelled value keeps it in force.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from acp.identity.principal import Principal
from acp.policy.schema import RESTRICTIVE, Effect, Policy, Rule, canonical


def folded(text: str) -> str:
    """Return the NFKC-normalised, case-folded, trimmed form a restriction compares on.

    Upstreams may read case, whitespace and full-width variants as the same value, so a
    deny must too.
    """
    return unicodedata.normalize("NFKC", text).casefold().strip()


class Verdict(StrEnum):
    """What a policy decided: allow, deny or hold for approval (ADR 0048)."""

    ALLOW = "allow"
    DENY = "deny"
    APPROVAL = "approval"


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of evaluating one request against a policy.

    ``requires_approval`` is a separate flag so ``allowed`` stays a boolean: a held
    call has ``allowed=False``, and every ``if decision.allowed`` check fails closed.
    The two are never both true (asserted in the tests).
    """

    allowed: bool
    rule: str | None
    """The deciding rule's name (audited), or ``None`` for the deny default, which never allows."""

    requires_approval: bool = False
    """A matching rule said this needs a person; not yet permitted."""

    @property
    def verdict(self) -> Verdict:
        if self.requires_approval:
            return Verdict.APPROVAL
        return Verdict.ALLOW if self.allowed else Verdict.DENY

    @property
    def reason(self) -> str:
        """A short human-readable account, for logs and error messages."""
        if self.rule is None:
            return "denied by default (no rule matched)"
        verb = {
            Verdict.ALLOW: "allowed",
            Verdict.DENY: "denied",
            Verdict.APPROVAL: "held for approval",
        }[self.verdict]
        return f"{verb} by rule {self.rule!r}"


def matches_without_arguments(rule: Rule, subject: str, actor: str | None, tool: str) -> bool:
    """Return whether the rule's identity and tool fields hold, ignoring arguments.

    Shared with pre-dispatch (ADR 0043), which runs before arguments exist, so the
    match logic exists once (ADR 0030).
    """
    if rule.subjects and subject not in rule.subjects:
        return False
    if rule.actors and (actor is None or actor not in rule.actors):
        return False
    if not rule.tools or tool in rule.tools:
        return True
    # Restrictions also match a folded tool name (ADR 0068 applied to the name);
    # a grant still needs the exact name.
    return rule.effect in RESTRICTIVE and folded(tool) in {folded(t) for t in rule.tools}


def _rule_matches(
    rule: Rule,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, object],
) -> bool:
    """Return whether the rule matches the request, arguments read per effect (ADR 0068)."""
    if not matches_without_arguments(rule, subject, actor, tool):
        return False
    restrictive = rule.effect in RESTRICTIVE
    for name, allowed in rule.args.items():
        value = canonical(arguments[name]) if name in arguments else None
        if restrictive:
            if value is not None and folded(value) not in {folded(a) for a in allowed}:
                return False
        elif value is None or value not in allowed:
            return False
    return True


def evaluate(
    policy: Policy,
    principal: Principal,
    tool: str,
    arguments: Mapping[str, object] | None = None,
) -> Decision:
    """Decide whether ``principal`` may call ``tool`` under ``policy``.

    Pure, no I/O. ``tool`` is the qualified name (``upstream__tool``, ADR 0003).
    ``arguments`` defaults to empty, which no argument-scoped allow can match.
    """
    args = arguments if arguments is not None else {}
    actor = principal.actor.subject if principal.actor else None
    for rule in policy.rules:
        if _rule_matches(rule, principal.subject, actor, tool, args):
            return decision_for(rule)
    return Decision(allowed=False, rule=None)


def decision_for(rule: Rule) -> Decision:
    """Return the decision a matching rule produces; shared with the simulator."""
    return Decision(
        allowed=rule.effect is Effect.ALLOW,
        rule=rule.name,
        requires_approval=rule.effect is Effect.REQUIRE_APPROVAL,
    )


PERMISSIBLE: Final = frozenset({Effect.ALLOW, Effect.REQUIRE_APPROVAL})
"""Effects under which a call may still proceed, so the fast path must not refuse it."""


def could_ever_allow(policy: Policy, principal: Principal, tool: str) -> bool:
    """Could any argument mapping make this call permitted?

    ``False`` means no arguments could permit the call, so refusing now agrees with the
    full check. ``True`` means only "not provably refused" and is not a permission.
    Walking rules in order (first match wins, ADR 0026): a matching allow or
    ``require_approval`` (ADR 0048) returns ``True``; an argument-free deny returns
    ``False``; an argument-scoped deny is skipped; the end is the deny default (ADR 0025).

    Used by pre-dispatch (ADR 0043) and catalogue filtering (ADR 0072).
    """
    actor = principal.actor.subject if principal.actor else None
    for rule in policy.rules:
        if not matches_without_arguments(rule, principal.subject, actor, tool):
            continue
        if rule.effect in PERMISSIBLE:
            return True
        if not rule.args:
            return False
    return False
