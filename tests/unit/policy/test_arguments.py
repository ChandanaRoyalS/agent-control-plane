"""Typed argument constraints, and the three bypasses they close.

Every case in the first class is a call that walked past a restrictive rule
before ADR 0060, and the reason each one did is the same: `str()` is not a
comparison between a YAML value and a JSON one.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from acp.policy.arguments import MAX_MATCHED_CHARS, MAX_VALUE_DEPTH, ArgConstraint, Outcome


def check(constraint: dict[str, Any] | list[Any], supplied: Any, *, exists: bool = True) -> Outcome:
    return ArgConstraint.model_validate(constraint).check(supplied, exists=exists)


class TestTheBypasses:
    """Reproduced from the external review of v1.0.0, verbatim."""

    def test_a_list_containing_the_value_matches(self) -> None:
        """`{"dataset": ["production"]}` rendered as `"['production']"` and
        missed a rule written `[production]`."""
        assert check(["production"], ["production"]) is Outcome.MATCH

    def test_a_mapping_is_undecidable_rather_than_a_miss(self) -> None:
        """`{"dataset": {"name": "production"}}` rendered as a Python repr.

        There is no way to know which member the author meant, so the answer is
        neither "matches" nor "does not" — and answering "does not" is what let
        the broad allow behind the guard take the call.
        """
        assert check(["production"], {"name": "production"}) is Outcome.UNDECIDABLE

    def test_a_float_matches_the_integer_it_equals(self) -> None:
        """`limit: 1000.0` rendered as `"1000.0"` and missed a deny on `1000`."""
        assert check([1000], 1000.0) is Outcome.MATCH

    def test_a_boolean_does_not_match_the_number_one(self) -> None:
        """Python says `True == 1`. A policy that cannot tell them apart has a
        type-confusion bug of its own."""
        assert check([1], True) is Outcome.NO_MATCH
        assert check([True], 1) is Outcome.NO_MATCH
        assert check([True], True) is Outcome.MATCH

    def test_a_string_does_not_match_the_number_it_spells(self) -> None:
        assert check(["1000"], 1000) is Outcome.NO_MATCH
        assert check([1000], "1000") is Outcome.NO_MATCH


class TestScalarsThatAreSimplyDifferent:
    """The other direction, and the reason `UNDECIDABLE` is a small set.

    A scalar of the wrong type is an *answer*: any author can see that
    `"production"` and `5` are different values. Calling that undecidable would
    fire every deny rule on every unrelated call, and a control that refuses
    honest traffic is one somebody switches off.
    """

    def test_a_different_string_is_a_clean_miss(self) -> None:
        assert check(["production"], "staging") is Outcome.NO_MATCH

    def test_a_number_against_a_string_constraint_is_a_clean_miss(self) -> None:
        assert check(["production"], 5) is Outcome.NO_MATCH

    def test_null_is_a_value_not_a_puzzle(self) -> None:
        assert check(["production"], None) is Outcome.NO_MATCH
        assert check([None], None) is Outcome.MATCH

    def test_an_empty_list_satisfies_nothing(self) -> None:
        assert check(["production"], []) is Outcome.NO_MATCH


class TestListsAreAddressedElementwise:
    def test_any_element_matching_is_a_match(self) -> None:
        assert check(["production"], ["staging", "production"]) is Outcome.MATCH

    def test_an_unreadable_element_cannot_dilute_a_hit(self) -> None:
        """Appending a mapping to a list must not turn a MATCH into a puzzle —
        a puzzle is weaker than a hit for an allow rule."""
        assert check(["production"], ["production", {"x": 1}]) is Outcome.MATCH

    def test_an_unreadable_element_beats_a_clean_miss(self) -> None:
        assert check(["production"], ["staging", {"x": 1}]) is Outcome.UNDECIDABLE

    def test_nesting_past_the_bound_is_undecidable(self) -> None:
        buried: Any = "production"
        for _ in range(MAX_VALUE_DEPTH + 2):
            buried = [buried]
        assert check(["production"], buried) is Outcome.UNDECIDABLE


class TestOperators:
    def test_range_bounds(self) -> None:
        assert check({"gt": 1000}, 1001) is Outcome.MATCH
        assert check({"gt": 1000}, 1000) is Outcome.NO_MATCH
        assert check({"gte": 1000, "lte": 2000}, 1500) is Outcome.MATCH
        assert check({"gte": 1000, "lte": 2000}, 2001) is Outcome.NO_MATCH

    def test_a_range_against_a_non_number_is_undecidable(self) -> None:
        """`limit: {gt: 1000}` against `limit: "lots"` is a question this
        constraint cannot answer, so the guard fires."""
        assert check({"gt": 1000}, "lots") is Outcome.UNDECIDABLE
        assert check({"gt": 0}, True) is Outcome.UNDECIDABLE

    def test_not_equals_inverts_a_decision_but_not_a_puzzle(self) -> None:
        assert check({"not_equals": ["production"]}, "staging") is Outcome.MATCH
        assert check({"not_equals": ["production"]}, "production") is Outcome.NO_MATCH
        assert check({"not_equals": ["production"]}, {"n": 1}) is Outcome.UNDECIDABLE

    def test_matches_runs_over_strings_only(self) -> None:
        assert check({"matches": "^/var/"}, "/var/x") is Outcome.MATCH
        assert check({"matches": "^/var/"}, "/etc/x") is Outcome.NO_MATCH
        assert check({"matches": "^/var/"}, 5) is Outcome.UNDECIDABLE

    def test_matches_gives_up_rather_than_scanning_an_unbounded_string(self) -> None:
        """The pattern is the operator's and the subject is the caller's, which
        makes backtracking the caller's choice. Bounded, and past the bound the
        guard fires rather than the check being skipped."""
        assert check({"matches": "x"}, "x" * (MAX_MATCHED_CHARS + 1)) is Outcome.UNDECIDABLE

    def test_present_is_the_only_operator_with_a_view_on_absence(self) -> None:
        assert check({"present": True}, None, exists=True) is Outcome.MATCH
        assert check({"present": True}, None, exists=False) is Outcome.NO_MATCH
        assert check({"present": False}, None, exists=False) is Outcome.MATCH

    def test_every_other_constraint_misses_an_absent_argument(self) -> None:
        assert check(["production"], None, exists=False) is Outcome.NO_MATCH


class TestTheSchemaRefusesAmbiguity:
    def test_two_operator_families_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ArgConstraint.model_validate({"gt": 1, "equals": [2]})

    def test_no_operator_at_all_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ArgConstraint.model_validate({})

    def test_an_empty_value_list_is_rejected(self) -> None:
        """It would match nothing, which is a rule that does nothing — almost
        certainly a truncated file rather than an intention."""
        with pytest.raises(ValidationError):
            ArgConstraint.model_validate({"equals": []})

    def test_a_non_scalar_constraint_value_is_rejected(self) -> None:
        """A constraint on part of a structure must name that part as its own
        argument, rather than being written as a nested literal nobody can
        compare."""
        with pytest.raises(ValidationError):
            ArgConstraint.model_validate({"equals": [{"name": "production"}]})

    def test_an_invalid_regex_is_rejected_at_load_time(self) -> None:
        with pytest.raises(ValidationError):
            ArgConstraint.model_validate({"matches": "([unclosed"})


class TestNormalisationRunsOnlyWhereLooserIsSafer:
    """The second half of the review's argument bypass (ADR 0068).

    ADR 0060 fixed type confusion — a list, a mapping, a float. It left string
    normalisation alone, so a deny rule was still bypassable by pressing shift.
    """

    def guard(self, supplied: Any) -> Outcome:
        """As a `deny` or `require_approval` rule sees it."""
        return ArgConstraint(equals=("production",)).check(supplied, exists=True, restrictive=True)

    def grant(self, supplied: Any) -> Outcome:
        """As an `allow` rule sees it."""
        return ArgConstraint(equals=("public",)).check(supplied, exists=True, restrictive=False)

    def test_a_guard_matches_through_case_and_padding(self) -> None:
        for supplied in ("production", "Production", "PRODUCTION", "production ", " production"):
            assert self.guard(supplied) is Outcome.MATCH, supplied

    def test_a_guard_matches_through_unicode_compatibility_forms(self) -> None:
        """A full-width capital renders as the letter an author typed and is a
        different code point. NFKC first, before case and padding."""
        assert self.guard("\uff30roduction") is Outcome.MATCH  # U+FF30, renders as "P"

    def test_a_guard_still_does_not_match_a_different_value(self) -> None:
        """Looser is not *loose*. Normalisation must not turn a guard into one
        that fires on everything — that is how a control gets switched off."""
        assert self.guard("staging") is Outcome.NO_MATCH
        assert self.guard("production-replica") is Outcome.NO_MATCH

    def test_a_grant_demands_the_exact_value(self) -> None:
        """**Why blanket normalisation would be a bug in the other direction.**

        An `allow` on `doc_id: [public]` that also matched `PUBLIC` would grant
        a document the author never named. If the upstream treats them as
        different documents, that is an authorization bug introduced by a
        convenience.
        """
        assert self.grant("public") is Outcome.MATCH
        for supplied in ("Public", "PUBLIC", "public "):
            assert self.grant(supplied) is Outcome.NO_MATCH, supplied

    def test_not_equals_inverts_the_looseness(self) -> None:
        """**The case that is easy to get backwards.**

        `allow ... not_equals: [production]` means "allow anything that is not
        production". Against `"Production"` the inner equality must be *loose*,
        so the negation refuses — otherwise the rule permits production access
        to anybody who holds down shift.
        """
        permissive = ArgConstraint(not_equals=("production",))

        assert permissive.check("staging", exists=True, restrictive=False) is Outcome.MATCH
        assert permissive.check("Production", exists=True, restrictive=False) is Outcome.NO_MATCH

    def test_not_equals_under_a_guard_is_strict(self) -> None:
        """And the mirror: `deny ... not_equals: [production]` denies everything
        that is not production, so the inner equality must be *strict* — a
        loosely-matched `"Production"` should suppress the denial only when it
        is really the value the author exempted."""
        restrictive = ArgConstraint(not_equals=("production",))

        assert restrictive.check("production", exists=True, restrictive=True) is Outcome.NO_MATCH
        assert restrictive.check("staging", exists=True, restrictive=True) is Outcome.MATCH

    def test_a_guard_regex_is_case_insensitive_and_a_grant_regex_is_not(self) -> None:
        pattern = ArgConstraint(matches="^/var/")

        assert pattern.check("/VAR/x", exists=True, restrictive=True) is Outcome.MATCH
        assert pattern.check("/VAR/x", exists=True, restrictive=False) is Outcome.NO_MATCH

    def test_numbers_are_untouched_by_any_of_this(self) -> None:
        """Normalisation is a string operation. A range constraint compares
        numbers and has no case to fold."""
        for restrictive in (True, False):
            assert (
                ArgConstraint(gt=1000).check(1001, exists=True, restrictive=restrictive)
                is Outcome.MATCH
            )
