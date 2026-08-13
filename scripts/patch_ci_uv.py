#!/usr/bin/env python3
"""Put `uv` on the compose job's PATH. Asserted, idempotent.

`.github/workflows/ci.yml` is a drift file and is never shipped whole; the
anchor is checked before anything is written.

**The bug.** Task 57's wiring added a step to the `image · compose · smoke` job
that runs the real verifier against the chain the real container wrote:

    uv run acp audit verify --log-file audit/audit.jsonl

That job installs Docker and nothing else. `uv` exists on the runner only in
the `quality` job, which installs it explicitly. So the step failed with
`uv: command not found` and exit 127 — a shell error, not a verification
failure, which is why three runs went red without the audit feature being
wrong in any way.

**Why the verifier runs on the runner and not in the container.** The obvious
cheaper fix is `docker compose exec gateway acp audit verify`, which needs no
Python on the runner at all. Rejected: the whole reason this step exists is that
every unit test in `tests/unit/audit` would still pass if the gateway never
called the audit log, and every integration test drives an in-process app. This
is the one place the artifact is produced by a container and checked from
outside it. Verifying with the same image that did the writing hands the check
back to the thing under test — the chain would then be consistent-with-itself
as computed by one binary, which is a claim about that binary rather than about
the log.

The cost is one dependency install in a job that is already twenty minutes of
Docker. `--no-dev` keeps it to the runtime set: this job needs one command, not
pytest.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CI = Path(".github/workflows/ci.yml")

# Unique in the file: only the `image` job sets up Buildx. Anchoring here rather
# than beside the verify step is deliberate — see the comment in the block
# below for why the install goes first.
ANCHOR = """      - name: Set up Buildx
        uses: docker/setup-buildx-action@v3
"""

STEPS = """      # `uv` is not on a GitHub runner by default. The `quality` job installs
      # it and this one did not, so the audit-verification step below died with
      # `uv: command not found` — a shell error dressed up as a failed
      # verification, which is the most misleading way this step could break.
      #
      # Installed HERE, before the image builds, rather than immediately before
      # the step that needs it: a dependency problem then fails in fifteen
      # seconds instead of after two `docker build`s and a Keycloak boot.
      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
          cache-dependency-glob: "uv.lock"

      - name: Install the verifier
        # `--no-dev`: this job runs exactly one command. pytest, mypy and ruff
        # belong to `quality` and installing them here would buy nothing but
        # wall clock.
        #
        # The verifier runs on the RUNNER, not inside the gateway container.
        # `docker compose exec gateway acp audit verify` would be cheaper and
        # would hand the check back to the thing under test — a chain declared
        # consistent by the same image that wrote it is a claim about that
        # image. Checking from outside is the entire point of this step.
        run: uv sync --no-dev

"""

# Not edited — asserted. If the verify step is gone, installing `uv` fixes
# nothing and this patch would report success over a job that proves less than
# it did before.
VERIFY_STEP = "acp audit verify --log-file audit/audit.jsonl"


def main() -> int:
    path = ROOT / CI
    print(f"Putting uv on the compose job's PATH in {CI}")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if VERIFY_STEP not in text:
        msg = (
            f"{CI} has no step running `{VERIFY_STEP}`. Installing uv would then "
            f"fix nothing. NOTHING HAS BEEN WRITTEN. Check that this branch has "
            f"task 57's CI wiring."
        )
        raise SystemExit(msg)

    if STEPS in text:
        print("  already applied")
        print("done.")
        return 0

    if ANCHOR not in text:
        msg = (
            f"{CI} does not contain the Buildx step this patch anchors on, and "
            f"does not already have the change. NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    path.write_text(text.replace(ANCHOR, STEPS + ANCHOR, 1), encoding="utf-8")
    print("  applied: uv installed before the images are built")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
