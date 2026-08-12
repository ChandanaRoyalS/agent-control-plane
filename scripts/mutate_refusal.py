#!/usr/bin/env python3
"""Break the refusal on purpose, and check the tests notice.

    uv run python scripts/mutate_refusal.py

The third harness in this repository, and the one guarding the most
counter-intuitive property in it. `tests/unit/firewall/test_decision.py` and
`tests/integration/test_firewall_refusal.py` assert that a refusal withholds the
document *and does not quote it*. Both pass. So would a pair of empty files —
and this failure has the same shape as the result cache's: nothing breaks,
nothing errors, the caller receives a plausible message, and the payload arrives
in the model's context wearing the gateway's authority.

So: introduce each mistake, one at a time, and require the assertion meant to
catch it to be the one that goes red. The plumbing is imported from
`mutate_no_passthrough` rather than copied, so there is one implementation of
the dangerous part.

Each mutation is something a reasonable engineer writes:

1. **Explain the refusal by quoting the evidence.** The first thing anybody
   does, because "blocked" with no reason is a bad error message. It is also the
   attack: the evidence is a span of the attacker's document, and the notice is
   delivered to the model outside any fence.
2. **Lower the bar to MEDIUM.** The "surely we should catch more" edit. Aimed at
   the condition that no live document currently exercises, which is exactly why
   it needs a harness rather than a comment.
3. **Ignore whether hosts are configured.** The tidying-up edit — the condition
   looks redundant next to the enforceable list. It is what stands between this
   gateway and refusing every wiki page that has a logo on it.
4. **Cache a result whose tail was never screened.** The performance edit. Turns
   one unexamined document into every later caller's answer for the length of
   its ttl.
5. **Fence the refusal like any other result.** The consistency edit, and the
   one that undoes ADR 0037: once the gateway's own notices are fenced, a fenced
   block no longer means "an upstream said this".

Safety
------

Same as its siblings: the script edits files in place, restores them in a
`finally`, and refuses to start unless `git status` is clean, so `git checkout .`
is a complete recovery if it ever dies before the restore.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mutate_no_passthrough import Mutation, apply, failing_tests, working_tree_is_clean

DECISION = "src/acp/firewall/decision.py"
SERVER = "src/acp/gateway/server.py"
UNIT = "tests/unit/firewall/test_decision.py"
INTEGRATION = "tests/integration/test_firewall_refusal.py"

MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="explain the refusal by quoting the evidence",
        path=DECISION,
        anchor='    labels = ", ".join(sorted({finding.label for finding in triggers}))',
        replacement=(
            '    labels = ", ".join(sorted({f"{f.label}: {f.evidence}" for f in triggers}))'
        ),
        # The end-to-end suite, deliberately. A unit test proves the string; only
        # this proves that what reached the socket does not contain the
        # document — which is the form of the claim that matters, because what a
        # model reads is bytes.
        caught_by=frozenset({"test_the_payload_never_reaches_the_caller"}),
        suite=INTEGRATION,
    ),
    Mutation(
        name="lower the bar from HIGH to MEDIUM",
        path=DECISION,
        anchor="        if finding.confidence is Confidence.HIGH",
        replacement="        if finding.confidence is not Confidence.LOW",
        # No detector on the enforceable list reports anything but HIGH today, so
        # nothing in the corpus can catch this. The assertion that does is
        # written against a hand-made finding, which is the only way to make a
        # constraint on the future falsifiable in the present.
        caught_by=frozenset(
            {"test_a_medium_finding_from_an_enforceable_detector_still_does_not_withhold"}
        ),
        suite=UNIT,
    ),
    Mutation(
        name="enforce the image detector even with no hosts configured",
        path=DECISION,
        anchor="        and (hosts_configured or finding.detector not in HOST_DEPENDENT)",
        replacement="        and (True or finding.detector not in HOST_DEPENDENT)  # noqa: SIM222",
        caught_by=frozenset({"test_an_image_cannot_withhold_a_result_until_hosts_are_configured"}),
        suite=UNIT,
    ),
    Mutation(
        name="cache a result whose tail was never screened",
        path=DECISION,
        anchor="        return not self.refused and not self.screening.truncated",
        replacement="        return not self.refused",
        caught_by=frozenset({"test_a_document_whose_tail_was_never_examined_may_not_be_cached"}),
        suite=UNIT,
    ),
    Mutation(
        name="fence the gateway's own refusal like an upstream result",
        path=SERVER,
        anchor="                return to_mcp_call_tool_result(inspection.result)",
        replacement=(
            "                return to_mcp_call_tool_result(\n"
            "                    _framed(inspection.result, params.name, provenance)\n"
            "                )"
        ),
        caught_by=frozenset({"test_the_refusal_is_not_fenced_as_retrieved_data"}),
        suite=INTEGRATION,
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

    print("Breaking the injection firewall's refusal on purpose.\n")
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
        print("The refusal is not actually being tested on those properties.")
        return 1
    print(f"all {len(MUTATIONS)} mutations were caught by the assertion meant to catch them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
