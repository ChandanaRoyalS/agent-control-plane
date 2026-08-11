#!/usr/bin/env python3
"""Break the no-passthrough invariant on purpose, and check the test notices.

    uv run python scripts/mutate_no_passthrough.py

`tests/integration/test_no_passthrough.py` asserts that the inbound token never
reaches an upstream. It passes. So would an empty file. A security test that has
never been observed to fail is a claim about the person who wrote it, not about
the system — and this project has already shipped one of those: 297 green tests
certifying an MCP client no real server would have accepted a request from.

So this script introduces the leak, one form at a time, and asserts that the
suite goes red *and that the right assertion is the one that goes red*. A
mutation that is caught by an unrelated test is a mutation that was not really
caught: it means the leak was detected by accident, and the accident may not
recur next time somebody rearranges the code.

Each mutation is a bug somebody could plausibly write:

1. **Forward the caller's token in a second header.** The "compatibility shim"
   version — the upstream wanted `X-Forwarded-Authorization`, someone obliged.
2. **Log the token.** The debugging version, left in. A credential in a log
   line has left the process just as surely as one in a header, and it lands
   somewhere with longer retention and a wider audience.
3. **Put it in the request envelope.** The `params._meta` version, which is an
   extension point and therefore attracts passengers.

Safety
------

The script edits files in place and restores them in a `finally`, which is not
by itself good enough — so it refuses to start unless `git status` is clean. If
it ever dies in a way that skips the restore, `git checkout .` is a complete
recovery and the refusal guarantees that costs nothing.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITE = "tests/integration/test_no_passthrough.py"

CLIENT = "src/acp/upstream/client.py"
EXCHANGE = "src/acp/identity/exchange.py"

READER = "from acp.identity.principal import current_subject_token"


@dataclass(frozen=True)
class Mutation:
    """One plausible bug, and the assertion that has to be the one to catch it."""

    name: str
    path: str
    anchor: str
    replacement: str
    caught_by: frozenset[str]
    suite: str = SUITE
    """Which suite must notice. Defaulted, so the passthrough mutations read as
    they always did, and settable so a sibling harness can reuse this machinery
    for a different invariant rather than copying the plumbing."""


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="forward the caller's token in a second header",
        path=CLIENT,
        anchor="            headers[credential[0]] = credential[1]\n",
        replacement=(
            "            headers[credential[0]] = credential[1]\n"
            f"        {READER}\n\n"
            "        _leak = current_subject_token()\n"
            "        if _leak:\n"
            '            headers["X-Forwarded-Authorization"] = f"Bearer {_leak}"\n'
        ),
        caught_by=frozenset(
            {
                "test_no_path_sends_the_inbound_token_to_an_upstream",
                # And the static alarm, because the leak needed a second reader
                # to exist at all. Two independent detections of one bug.
                "test_exactly_one_module_can_read_the_inbound_token",
            }
        ),
    ),
    Mutation(
        name="log the token alongside the exchange",
        path=EXCHANGE,
        anchor='            "auth.exchanged",\n            extra={\n',
        replacement=(
            '            "auth.exchanged",\n'
            "            extra={\n"
            '                "subject_token": current_subject_token(),\n'
        ),
        caught_by=frozenset({"test_no_path_writes_the_inbound_token_to_a_log"}),
    ),
    Mutation(
        name="carry the token in the request envelope",
        path=CLIENT,
        anchor="            headers[credential[0]] = credential[1]\n",
        replacement=(
            "            headers[credential[0]] = credential[1]\n"
            f"        {READER}\n\n"
            "        _leak = current_subject_token()\n"
            "        if _leak:\n"
            '            body["params"]["_meta"]["acp/callerToken"] = _leak\n'
        ),
        caught_by=frozenset(
            {
                "test_no_path_sends_the_inbound_token_to_an_upstream",
                "test_exactly_one_module_can_read_the_inbound_token",
            }
        ),
    ),
)


def working_tree_is_clean() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and not result.stdout.strip()


def failing_tests(suite: str = SUITE) -> set[str]:
    """Which tests in the suite failed, by name.

    Names rather than a count, because "something failed" is not evidence that
    the *right* thing failed — and a mutation caught by the wrong assertion is a
    mutation that got away.

    Raises when the run produced no result at all. A pytest that died during
    collection reports zero failures, which this script would otherwise read as
    "the mutation survived" — a true statement arrived at by accident, and one
    that would send somebody looking for a hole in the test suite rather than at
    a broken environment.
    """
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            suite,
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
            # Neutralise `addopts`, which carries `--cov-fail-under=80`. Running
            # one file under that threshold fails the run for a reason that has
            # nothing to do with the mutation — and every mutation would then
            # look caught, which is the precise failure this script exists to
            # detect in somebody else's test.
            "-o",
            "addopts=",
            # A missing optional plugin turns its config key into a config-time
            # warning, and `filterwarnings = ["error"]` turns that into a dead
            # run. Whether a mutation was caught should not depend on which
            # plugins happen to be installed where this is run.
            "-W",
            "ignore::pytest.PytestConfigWarning",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if not any(word in result.stdout for word in (" passed", " failed", " error")):
        detail = (result.stdout + result.stderr).strip().splitlines()[-15:]
        msg = "pytest produced no result:\n" + "\n".join(detail)
        raise SystemExit(msg)

    return {
        line.split("::")[-1].split()[0]
        for line in result.stdout.splitlines()
        if line.startswith("FAILED")
    }


def apply(mutation: Mutation) -> str:
    """Write the bug in, returning the original text for the restore."""
    path = ROOT / mutation.path
    original = path.read_text(encoding="utf-8")
    if mutation.anchor not in original:
        msg = (
            f"{mutation.path} no longer contains the anchor for "
            f"{mutation.name!r}. The mutation has drifted from the code it was "
            f"written against, and a mutation that cannot be applied proves "
            f"nothing — fix the anchor rather than deleting the case."
        )
        raise SystemExit(msg)
    path.write_text(original.replace(mutation.anchor, mutation.replacement, 1), encoding="utf-8")
    return original


def main() -> int:
    if not working_tree_is_clean():
        print(
            "refusing to run with uncommitted changes: this script edits source "
            "files in place, and a clean tree is what makes `git checkout .` a "
            "complete recovery if it dies badly.",
            file=sys.stderr,
        )
        return 1

    print("Breaking the no-passthrough invariant on purpose.\n")
    survivors: list[str] = []

    for mutation in MUTATIONS:
        path = ROOT / mutation.path
        original = apply(mutation)
        try:
            failed = failing_tests(mutation.suite)
        finally:
            path.write_text(original, encoding="utf-8")

        expected = mutation.caught_by
        if expected <= failed:
            extra = failed - expected
            note = f" (also: {', '.join(sorted(extra))})" if extra else ""
            print(f"  caught   {mutation.name}{note}")
        else:
            survivors.append(mutation.name)
            missed = ", ".join(sorted(expected - failed)) or "nothing failed"
            print(f"  SURVIVED {mutation.name} — expected to fail: {missed}")

    print()
    if survivors:
        print(f"FAILED: {len(survivors)} mutation(s) survived — {'; '.join(survivors)}")
        print("The invariant is not actually being tested on those paths.")
        return 1
    print(f"all {len(MUTATIONS)} mutations were caught by the assertion meant to catch them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
