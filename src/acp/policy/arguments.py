"""Matching a rule's argument constraint against the value a call supplied.

The old implementation was one line — ``str(arguments[name]) in allowed`` — and
an external review turned it into three bypasses in a minute:

```
rule: require_approval db__delete where dataset in [production]
{"dataset": "production"}           -> held for a human
{"dataset": ["production"]}         -> allowed, no human asked
{"dataset": {"name": "production"}} -> allowed, no human asked

rule: deny db__query where limit in ["1000"]
{"limit": 1000}   -> denied
{"limit": 1000.0} -> allowed
```

Every one of those is the same mistake: a tool argument is a **JSON value**, a
policy constraint is a **YAML value**, and `str()` is not a comparison between
them. It is a rendering of one of them into a form where `1000.0`, `True` and
`['prod']` are strings that happen not to be equal to the string the author
wrote. The failures all land in the same direction — a *restrictive* rule
silently not firing, and the broad allow behind it taking the call.

## The rule this module enforces

Matching is **tri-state**, and the third state is the point.

``MATCH``       the constraint holds for this value.
``NO_MATCH``    the constraint definitely does not hold.
``UNDECIDABLE`` the value has a shape this constraint cannot address at all.

``UNDECIDABLE`` exists because "I cannot compare these" and "these are
different" are not the same answer, and the old code gave the second to both.
What the evaluator does with it is stated in `acp.policy.evaluate`, and it is
the only safe reading: **a guard that cannot tell, fires.** An undecidable
constraint matches a `deny` or `require_approval` rule and fails to match an
`allow` one, so both directions fail closed without the caller choosing.

The undecidable set is deliberately small — a dictionary where a scalar was
expected, a structure nested deeper than this module walks, a regex against a
number. A scalar of the wrong type is *not* undecidable: `"production"` and
`5` are different values and any author can see it. Making that undecidable
would fire every deny rule on every unrelated call, and a control that refuses
honest traffic is a control somebody switches off (ADR 0038).

A list is addressed elementwise, because `["production"]` is how half the tools
in the world spell "the production dataset" and an author who wrote
`dataset: [production]` plainly meant to catch it.
"""

from __future__ import annotations

import operator
import re
import unicodedata
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Final, Self

from pydantic import BaseModel, ConfigDict, model_validator

MAX_VALUE_DEPTH: Final = 4
"""How deep into a supplied argument value this module walks.

Beyond it the answer is ``UNDECIDABLE`` rather than ``NO_MATCH``, so a caller
cannot escape a restrictive rule by burying the value in nesting. Four is deeper
than any argument shape a policy can usefully talk about.
"""

MAX_MATCHED_CHARS: Final = 4096
"""How much of a string a ``matches`` constraint will run its pattern over.

The pattern comes from the operator and the subject comes from the caller, which
is the arrangement that makes catastrophic backtracking the caller's choice
rather than the operator's. Bounded, and past the bound the answer is
``UNDECIDABLE`` — the guard fires rather than the check being skipped.
"""


def loosely(value: str) -> str:
    """A string reduced to what an author plainly meant by it.

    NFKC first, so a full-width `\uff30roduction` or a compatibility ligature
    becomes the ASCII an author typed; then whitespace, because a value that
    arrived with a trailing space from a form field is the same value; then
    case.

    **Applied only where a looser match is the safer one** — see
    `_loose_inner`. Normalising everywhere would be a bug in the other
    direction: an `allow` on `doc_id: [public]` that also matched `PUBLIC` would
    grant a document the author did not name.
    """
    return unicodedata.normalize("NFKC", value).strip().casefold()


def _loose_inner(*, restrictive: bool, negated: bool) -> bool:
    """Whether the *string comparison* inside a constraint should be loose.

    The rule is one sentence: **a match should be easy to make when matching
    denies, and hard to make when matching permits.** Everything else follows,
    including the case that is easy to get backwards.

    | constraint | effect | inner comparison | why |
    |---|---|---|---|
    | `equals` | deny / approval | loose | matching denies, so match readily |
    | `equals` | allow | strict | matching permits, so demand the exact value |
    | `not_equals` | deny / approval | **strict** | the inner match *suppresses* the denial |
    | `not_equals` | allow | **loose** | the inner match *suppresses* the grant |

    `not_equals` inverts because the inner comparison is negated before it
    decides anything: `allow ... not_equals: [production]` against a supplied
    `"Production"` must not permit the call, which requires the inner equality to
    be *loose* so that the negation refuses it.
    """
    return restrictive != negated


class Outcome(StrEnum):
    """Whether a constraint held, did not hold, or could not be evaluated."""

    MATCH = "match"
    NO_MATCH = "no_match"
    UNDECIDABLE = "undecidable"


class ArgConstraint(BaseModel):
    """What one named argument must look like for its rule to match.

    Written in YAML either as a bare list — the shorthand, meaning "one of
    these" — or as a mapping of explicit operators:

    ```yaml
    args:
      dataset: [production, staging]      # shorthand for {equals: [...]}
      limit: {gt: 1000}
      path: {matches: "^/tmp/"}
      dry_run: {equals: [false]}          # a boolean, and only a boolean
      reason: {present: true}             # any value, but it must be there
    ```

    Exactly one operator family per argument, because a mapping with both
    `equals` and `gt` has an obvious reading and two plausible ones, and a
    policy language should have no clauses whose meaning a reader must guess.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    equals: tuple[Any, ...] | None = None
    """Any of these scalar values. The shorthand list desugars to this."""

    not_equals: tuple[Any, ...] | None = None
    """None of these scalar values."""

    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    """Numeric comparisons. A non-numeric value is ``UNDECIDABLE``, not
    ``NO_MATCH``: `limit: {gt: 1000}` against `limit: "lots"` is a question this
    constraint cannot answer, and the guard should fire."""

    matches: str | None = None
    """A regular expression, anchored by the author if they want anchoring, run
    over string values only."""

    present: bool | None = None
    """``true``: the argument must be supplied, with any value. ``false``: it
    must be absent. The only operator that has an opinion about a *missing*
    argument — every other constraint answers ``NO_MATCH`` for one."""

    @model_validator(mode="after")
    def _exactly_one_family(self) -> Self:
        families = {
            "equals": self.equals is not None,
            "not_equals": self.not_equals is not None,
            "range": any(v is not None for v in (self.gt, self.gte, self.lt, self.lte)),
            "matches": self.matches is not None,
            "present": self.present is not None,
        }
        chosen = [name for name, used in families.items() if used]
        if len(chosen) != 1:
            msg = (
                f"an argument constraint must use exactly one of "
                f"{sorted(families)}; got {chosen or 'nothing'}"
            )
            raise ValueError(msg)
        for name in ("equals", "not_equals"):
            values = getattr(self, name)
            if values is not None:
                if not values:
                    msg = f"`{name}` needs at least one value; an empty list matches nothing"
                    raise ValueError(msg)
                for value in values:
                    if not _is_scalar(value):
                        msg = (
                            f"`{name}` takes scalars (string, number, boolean, null); "
                            f"got {type(value).__name__}. A constraint on part of a "
                            f"structure must name that part as its own argument."
                        )
                        raise ValueError(msg)
        if self.matches is not None:
            try:
                re.compile(self.matches)
            except re.error as exc:
                msg = f"`matches` is not a valid regular expression: {exc}"
                raise ValueError(msg) from exc
        return self

    @model_validator(mode="before")
    @classmethod
    def _desugar(cls, value: Any) -> Any:
        """A bare list is the shorthand for ``equals``.

        Kept because it is what an operator writes when they are not thinking
        about this module, and what every existing policy file already says. Its
        *meaning* changed in 2.0.0 — from `str()` rendering to typed comparison —
        which is the whole point of ADR 0060 and is why that is a major bump
        rather than a patch.
        """
        if isinstance(value, (list, tuple)):
            return {"equals": tuple(value)}
        return value

    def check(self, supplied: Any, *, exists: bool, restrictive: bool = False) -> Outcome:
        """Whether this constraint holds for the value the call supplied."""
        if self.present is not None:
            return Outcome.MATCH if exists is self.present else Outcome.NO_MATCH
        if not exists:
            # Every other constraint is a claim about a value. A call that
            # omits the argument does not satisfy it — and does not puzzle it
            # either, so this is NO_MATCH rather than UNDECIDABLE.
            return Outcome.NO_MATCH
        if self.equals is not None:
            return _any_of(
                self.equals, supplied, _loose_inner(restrictive=restrictive, negated=False)
            )
        if self.not_equals is not None:
            loose = _loose_inner(restrictive=restrictive, negated=True)
            return _negate(_any_of(self.not_equals, supplied, loose))
        if self.matches is not None:
            return _matches(self.matches, supplied, restrictive)
        return _in_range(self, supplied)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool, int, float))


def _negate(outcome: Outcome) -> Outcome:
    if outcome is Outcome.MATCH:
        return Outcome.NO_MATCH
    if outcome is Outcome.NO_MATCH:
        return Outcome.MATCH
    return Outcome.UNDECIDABLE


def _combine(outcomes: list[Outcome]) -> Outcome:
    """Any match wins; otherwise any puzzle wins; otherwise no match.

    The ordering is the safety property. A list containing one value this
    constraint understands and one it does not is a MATCH if the understood one
    matches — an attacker cannot dilute a hit by appending a dictionary to the
    list.
    """
    if Outcome.MATCH in outcomes:
        return Outcome.MATCH
    if Outcome.UNDECIDABLE in outcomes:
        return Outcome.UNDECIDABLE
    return Outcome.NO_MATCH


def _over_value(scalar: Callable[[Any], Outcome], supplied: Any, depth: int = 0) -> Outcome:
    """Apply a scalar test to a supplied value of any shape.

    The container handling is identical for every operator and is where the
    safety properties live, so it exists once: a mapping cannot be addressed and
    is a puzzle, a list is addressed elementwise, an empty list satisfies
    nothing, and nesting past `MAX_VALUE_DEPTH` is a puzzle rather than a pass.
    """
    if depth > MAX_VALUE_DEPTH:
        return Outcome.UNDECIDABLE
    if isinstance(supplied, dict):
        # No way to know which member the author meant. The guard fires.
        return Outcome.UNDECIDABLE
    if isinstance(supplied, (list, tuple)):
        if not supplied:
            return Outcome.NO_MATCH
        return _combine([_over_value(scalar, item, depth + 1) for item in supplied])
    return scalar(supplied)


def _any_of(allowed: tuple[Any, ...], supplied: Any, loose: bool = False) -> Outcome:
    """Whether ``supplied`` is one of ``allowed``, walking lists elementwise."""
    return _over_value(lambda value: _combine([_equal(a, value, loose) for a in allowed]), supplied)


def _equal(rule_value: Any, supplied: Any, loose: bool = False) -> Outcome:
    """Scalar equality that knows JSON's types apart.

    Booleans are checked before numbers because Python says ``True == 1``, and a
    policy that cannot tell ``dry_run: true`` from ``dry_run: 1`` is a policy
    with a type-confusion bug of its own.
    """
    if isinstance(rule_value, bool) or isinstance(supplied, bool):
        return Outcome.MATCH if rule_value is supplied else Outcome.NO_MATCH
    if rule_value is None or supplied is None:
        return Outcome.MATCH if rule_value is supplied else Outcome.NO_MATCH
    if isinstance(rule_value, (int, float)) and isinstance(supplied, (int, float)):
        # 1000 and 1000.0 are one number in JSON, and were two strings before.
        return Outcome.MATCH if rule_value == supplied else Outcome.NO_MATCH
    if isinstance(rule_value, str) and isinstance(supplied, str):
        if loose:
            return Outcome.MATCH if loosely(rule_value) == loosely(supplied) else Outcome.NO_MATCH
        return Outcome.MATCH if rule_value == supplied else Outcome.NO_MATCH
    # A scalar of a different type. Definitely a different value, and any author
    # can see that it is — so this is an answer, not a puzzle.
    return Outcome.NO_MATCH


def _matches(pattern: str, supplied: Any, loose: bool = False) -> Outcome:
    flags = re.IGNORECASE if loose else 0

    def against(value: Any) -> Outcome:
        if not isinstance(value, str):
            # A pattern against a number is a question about a rendering, and
            # which rendering is exactly the ambiguity this module removes.
            return Outcome.UNDECIDABLE
        if len(value) > MAX_MATCHED_CHARS:
            return Outcome.UNDECIDABLE
        return Outcome.MATCH if re.search(pattern, value, flags) is not None else Outcome.NO_MATCH

    return _over_value(against, supplied)


def _in_range(constraint: ArgConstraint, supplied: Any) -> Outcome:
    bounds = (
        (constraint.gt, operator.gt),
        (constraint.gte, operator.ge),
        (constraint.lt, operator.lt),
        (constraint.lte, operator.le),
    )

    def against(value: Any) -> Outcome:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return Outcome.UNDECIDABLE
        for bound, holds in bounds:
            if bound is not None and not holds(value, bound):
                return Outcome.NO_MATCH
        return Outcome.MATCH

    return _over_value(against, supplied)


ArgConstraints = dict[str, ArgConstraint]
"""A rule's whole argument section."""


def check_all(constraints: ArgConstraints, arguments: Any, *, restrictive: bool = False) -> Outcome:
    """Every constraint, ANDed, with the tri-state preserved.

    One ``NO_MATCH`` settles it: the rule does not apply. Otherwise one
    ``UNDECIDABLE`` makes the whole section undecidable, and the evaluator
    resolves that by the rule's effect.
    """
    if not constraints:
        return Outcome.MATCH
    supplied = arguments if isinstance(arguments, dict) else {}
    outcomes = [
        constraint.check(supplied.get(name), exists=name in supplied, restrictive=restrictive)
        for name, constraint in constraints.items()
    ]
    if Outcome.NO_MATCH in outcomes:
        return Outcome.NO_MATCH
    if Outcome.UNDECIDABLE in outcomes:
        return Outcome.UNDECIDABLE
    return Outcome.MATCH


__all__ = ["ArgConstraint", "ArgConstraints", "Outcome", "check_all", "loosely"]
