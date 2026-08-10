"""The policy schema: what a rulebook is allowed to say.

Task 32 is the rulebook, not the engine. These models load and validate a policy
document at startup; nothing here decides a request. What they guarantee is that
by the time task 33's evaluator exists, the policy it reads is well-formed and
its default is *deny* — a policy cannot be written, by omission or by typo, that
lets an unmatched request through.

Deny-by-default is structural rather than configurable on purpose. A boolean
`default_allow` somewhere is a boolean somebody flips for a demo and forgets, and
the failure it produces is the quiet kind: every request permitted, no error, no
log line that looks wrong. So the document's default is fixed at deny and the
only thing a rule can do is carve an *allow* out of it. There is no way to spell
"allow everything" except by writing a rule that says so, in the file, in the
diff.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# A rule name is a label for humans and for the audit log (a later task): which rule
# allowed this call. Constrained to the same shape as an upstream name so it is
# safe to put in a log field, a metric label, or a span attribute without
# quoting — lowercase alphanumeric with single hyphens.
_RULE_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

MAX_RULE_NAME_LENGTH = 48
"""Long enough to be descriptive (`allow-search-for-support-agents`), short
enough to stay readable in a log line or a metric label."""


class Effect(StrEnum):
    """What a matching rule does.

    Both effects exist even though the document default is already deny, because
    an explicit `deny` rule is not redundant with the default: it lets a narrow
    denial sit *in front of* a broad allow. "Support agents may call any tool on
    the CRM, except delete-record" is one allow and one deny, and without an
    explicit deny effect it could only be written as an allow-list of every tool
    but one — which silently grows a hole every time the CRM adds a tool.

    A str-valued enum so it round-trips through YAML as the word `allow` or
    `deny` rather than an integer nobody can read in a diff.
    """

    ALLOW = "allow"
    DENY = "deny"


class Rule(BaseModel):
    """One rule: whom it matches, what it matches, and what it then does.

    Every match field defaults to "matches anything", so an empty-bodied rule
    matches every request — which is exactly why the *default effect has no
    default* and must be written. A rule that matches everything and forgot to
    say allow-or-deny is the most dangerous line in the file, so the schema
    refuses to guess.

    Matching semantics (which task 33 will implement, and which the shape here
    commits to): a field set to a list matches when the request's value is in
    that list; a field left unset matches anything. All set fields must match —
    the fields are ANDed. This is deliberately the simplest thing that can
    express real rules; a richer matcher (globs, argument predicates) is a later
    task and would extend, not replace, this.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(max_length=MAX_RULE_NAME_LENGTH)
    """A label, unique within the document. Names the rule that allowed or
    denied a call in the audit log — an anonymous rule is a decision nobody can
    explain after the fact."""

    effect: Effect
    """Allow or deny. No default: see the class docstring. A rule that matches
    everything and omits this would be catastrophic, so the omission is an
    error, not a guess."""

    subjects: tuple[str, ...] = ()
    """Which human principals this rule matches. Empty means any subject.

    Matched against `Principal.subject`. "Any subject" is a real and common
    case — a rule about a tool that everyone may use — so empty is a legitimate
    value here, unlike `effect`. The safety comes from the document default
    being deny, not from forcing every rule to name subjects.
    """

    actors: tuple[str, ...] = ()
    """Which agents (workloads) this rule matches. Empty means any actor.

    Matched against the principal's actor identity. Separate from `subjects`
    because "which human may read this" and "which agent may act at all" are
    different questions (ADR 0015) — a compromised agent is denied here even
    when the human it acts for is allowed by `subjects`.
    """

    tools: tuple[str, ...] = ()
    """Which qualified tool names (`upstream__tool`, ADR 0003) this rule
    matches. Empty means any tool."""

    args: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    """Argument constraints, by argument name. Each entry maps an argument to the
    values it may take: the rule matches only when the call supplies that
    argument and its value is one of the listed ones. An unset ``args`` (the
    empty default) constrains nothing, so a rule keeps matching every call the
    way it did before this field existed — the same "unset means anything"
    semantics as `subjects` and `tools`, one level deeper.

    This is exact-value matching only, deliberately: it extends the membership
    model already in use rather than introducing operators, globs, or ranges,
    which would be a richer matcher and a later task. It is checked at *call*
    time, where the arguments exist; `tools/list` has no arguments, so a rule
    with `args` still makes its tool *visible*, and the argument check happens
    when the call is actually made (see `visible_tools` and `enforce_call`)."""

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not _RULE_NAME.match(value):
            msg = (
                f"rule name {value!r} must be lowercase alphanumeric with single "
                f"hyphens: it is used verbatim as an audit-log and metric label"
            )
            raise ValueError(msg)
        return value


class Policy(BaseModel):
    """A whole policy document: an ordered list of rules over a deny default.

    The default is not a field. It is the fixed behaviour of the engine task 33
    will build — a request matching no rule is denied — and it is stated here in
    the type so that no future edit can turn it into configuration. The only way
    the document expresses "allow" is a rule whose effect is allow.

    Order matters, and the model preserves it: task 33 evaluates rules top to
    bottom and the first match wins, which is what lets a narrow `deny` sit
    ahead of a broad `allow`. That evaluation order is a decision recorded in
    the ADR, not an accident of list iteration.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[Rule, ...] = ()
    """The rules, in evaluation order. Empty is valid and means deny everything:
    a gateway with an empty policy refuses every call rather than failing to
    start. That is the safe direction — a policy file that got truncated should
    lock the doors, not open them."""

    @field_validator("rules")
    @classmethod
    def _unique_names(cls, value: tuple[Rule, ...]) -> tuple[Rule, ...]:
        """Rule names must be unique, because the audit log identifies a
        decision by the name of the rule that made it. Two rules called
        `allow-search` make "allowed by allow-search" ambiguous — and the
        ambiguity surfaces in an incident review, which is the worst time."""
        seen: set[str] = set()
        for rule in value:
            if rule.name in seen:
                msg = (
                    f"rule name {rule.name!r} appears more than once; names must be "
                    f"unique because the audit log identifies decisions by them"
                )
                raise ValueError(msg)
            seen.add(rule.name)
        return value
