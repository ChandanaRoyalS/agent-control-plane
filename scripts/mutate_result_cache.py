#!/usr/bin/env python3
"""Break the result cache's isolation on purpose, and check the test notices.

    uv run python scripts/mutate_result_cache.py

`tests/integration/test_result_caching.py` asserts that one caller's cached tool
result never reaches another. It passes. So would an empty file — and this is
the assertion where that matters most, because the failure it guards has no
symptom at all. A leaked credential can be rotated and counted; a leaked
*result* is served, read, and never recorded anywhere. The upstream's audit log
shows one read by whoever asked first, which is true, and the second read
appears nowhere.

So: remove a field from the key, one at a time, and require the isolation test
to be the assertion that fails. The plumbing — the clean-tree refusal, the
in-place edit with a `finally` restore, the "caught by the *right* test" check —
is imported from `mutate_no_passthrough` rather than copied, so there is one
implementation of the dangerous part.

Each mutation is a key somebody could plausibly write:

1. **Drop the subject.** The classic: cache "the result of this tool with these
   arguments", which is what every general-purpose cache decorator does.
2. **Drop the actor.** The subtler one — right in most deployments, wrong in a
   gateway whose whole model is an agent acting *for* a human.
3. **Drop the arguments.** Not a cross-caller leak, but a caller served their
   own answer to a different question, which is its own kind of wrong.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mutate_no_passthrough import Mutation, apply, failing_tests, working_tree_is_clean

CACHE = "src/acp/results/cache.py"
SUITE = "tests/integration/test_result_caching.py"

ISOLATION = "test_a_second_caller_never_receives_the_first_ones_result"
ACTOR = "test_two_agents_acting_for_one_person_do_not_share_an_entry"

ANCHOR = """    material = json.dumps(
        [KEY_VERSION, subject, actor, upstream, tool, encoded_arguments],"""


def dropping(field: str) -> str:
    """The key material with one field removed."""
    kept = [
        name
        for name in ("KEY_VERSION", "subject", "actor", "upstream", "tool", "encoded_arguments")
        if name != field
    ]
    return f"    material = json.dumps(\n        [{', '.join(kept)}],"


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="drop the subject from the key",
        path=CACHE,
        anchor=ANCHOR,
        replacement=dropping("subject"),
        caught_by=frozenset({ISOLATION}),
        suite=SUITE,
    ),
    Mutation(
        name="drop the acting agent from the key",
        path=CACHE,
        anchor=ANCHOR,
        replacement=dropping("actor"),
        caught_by=frozenset({ACTOR}),
        suite=SUITE,
    ),
    Mutation(
        name="drop the arguments from the key",
        path=CACHE,
        anchor=ANCHOR,
        replacement=dropping("encoded_arguments"),
        # Not a cross-caller leak — the caller is still themselves — so the
        # isolation test is *not* the one that should catch it. Listed against
        # the same-caller test, because the observable failure is a caller being
        # handed their own answer to a question they did not ask.
        caught_by=frozenset({"test_the_same_caller_is_served_from_the_cache"}),
        suite=SUITE,
    ),
)


def main() -> int:
    if not working_tree_is_clean():
        print(
            "refusing to run with uncommitted changes: this script edits source "
            "files in place, and a clean tree is what makes `git checkout .` a "
            "complete recovery if it dies badly.",
            file=sys.stderr,
        )
        return 1

    print("Breaking the result cache's isolation on purpose.\n")
    survivors: list[str] = []

    for mutation in MUTATIONS:
        path = Path(__file__).resolve().parents[1] / mutation.path
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
        print("The cache key is not actually being tested on those fields.")
        return 1
    print(f"all {len(MUTATIONS)} mutations were caught by the assertion meant to catch them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
