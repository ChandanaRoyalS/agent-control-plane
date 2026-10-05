"""The policy schema, loaded and validated at startup; nothing here decides a request.

Deny-by-default is structural, not a setting: no ``default_allow`` exists to flip, so
allowing anything takes an explicit rule in the file (ADR 0025).
"""

from __future__ import annotations

import json
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Lowercase alphanumeric with single hyphens: safe unquoted in logs, metric labels, spans.
_RULE_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

MAX_RULE_NAME_LENGTH = 48
"""Descriptive yet readable in a log line or metric label."""


def canonical(value: object) -> str | None:
    """Return the JSON-spelled string a scalar compares as; ``None`` for a non-scalar.

    A non-scalar can neither satisfy a grant nor escape a restriction (ADR 0068).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int | float):
        return json.dumps(value)
    return None


def _canonical_value(value: object, name: str) -> str:
    form = canonical(value)
    if form is None:
        msg = (
            f"args.{name}: values must be strings, numbers or booleans, not {type(value).__name__}"
        )
        raise ValueError(msg)
    return form


class Effect(StrEnum):
    """What a matching rule does.

    An explicit ``deny`` lets a narrow denial sit ahead of a broad allow.
    ``require_approval`` is an effect so approvals can be scoped by subject, tool and
    argument (ADR 0031, ADR 0048).
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


RESTRICTIVE = frozenset({Effect.DENY, Effect.REQUIRE_APPROVAL})
"""Effects whose argument constraints a call clears only by a value outside the set (ADR 0068)."""


class Rule(BaseModel):
    """One rule: whom and what it matches, and its effect.

    A list field matches when the request's value is in it; an empty field matches
    anything; set fields are ANDed. ``effect`` has no default because an empty rule
    matches everything.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(max_length=MAX_RULE_NAME_LENGTH)
    """Unique label naming the deciding rule in the audit log."""

    effect: Effect
    """Required: omitting it on a match-everything rule must be an error, not a guess."""

    subjects: tuple[str, ...] = ()
    """Human principals matched against `Principal.subject`; empty means any."""

    actors: tuple[str, ...] = ()
    """Agents matched against the actor identity; empty means any (ADR 0015)."""

    tools: tuple[str, ...] = ()
    """Qualified tool names (`upstream__tool`, ADR 0003); empty means any."""

    args: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    """Argument name to set of values, checked at call time; empty constrains nothing.

    On an ``allow`` the call must supply the argument as a scalar exactly in the set;
    on a ``deny`` or ``require_approval`` only a scalar whose folded form is outside the
    set clears it, so a missing argument matches a restriction, not a grant (ADR 0068).
    YAML values are stored in canonical JSON form, so ``limit: [10]`` matches integer
    10. Plain membership: no operators, globs or ranges. `tools/list` has no
    arguments, so `args` does not hide a tool (see `visible_tools`)."""

    @field_validator("args", mode="before")
    @classmethod
    def _canonical_arg_values(cls, value: object) -> object:
        """Accept scalars and keep their canonical string form."""
        if not isinstance(value, dict):
            return value
        return {
            name: tuple(_canonical_value(v, name) for v in values)
            if isinstance(values, list | tuple)
            else values
            for name, values in value.items()
        }

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
    """An ordered list of rules over a fixed deny default.

    The default is deliberately not a field. Order is preserved because the first
    match wins (ADR 0026).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[Rule, ...] = ()
    """Rules in evaluation order; empty is valid and denies every call."""

    @field_validator("rules")
    @classmethod
    def _unique_names(cls, value: tuple[Rule, ...]) -> tuple[Rule, ...]:
        """Reject duplicate names, which would make audit attributions ambiguous."""
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

    @property
    def gates_calls(self) -> bool:
        """Whether any rule holds a call for a person (ADR 0048).

        Read at startup: only then are the approval store and operator channel built.
        """
        return any(rule.effect is Effect.REQUIRE_APPROVAL for rule in self.rules)
