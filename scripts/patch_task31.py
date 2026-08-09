#!/usr/bin/env python3
"""Wire the mutation harness into `make` and into CI. Asserted, idempotent.

    uv run python scripts/patch_task31.py

Two files this project deliberately never ships whole, because they drift:
`Makefile` and `.github/workflows/ci.yml`. Every edit asserts its anchor first
and aborts on the whole change if any is missing — a patch that half-applied
would be worse than one that refused, because the half that landed would look
like the whole thing.

Running it twice is a no-op and says so.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAKE_ANCHOR = """probe-resource:  ## Measure what Keycloak does with RFC 8707's `resource`"""

MAKE_HELP = "## Break the no-passthrough invariant on purpose, and check the test notices"
MAKE_TARGET = f"""prove-passthrough:  {MAKE_HELP}
	uv run python scripts/mutate_no_passthrough.py

"""

CI_ANCHOR = """      - name: Test
        run: uv run pytest
"""

CI_STEP = """      - name: Test
        run: uv run pytest

      # A security test that has never been seen to fail is a claim about
      # whoever wrote it. This breaks the no-passthrough invariant three ways and
      # fails the build if the suite does not notice — and if an anchor has
      # drifted, it fails loudly rather than quietly proving nothing.
      - name: Prove the no-passthrough test can fail
        run: uv run python scripts/mutate_no_passthrough.py
"""

PHONY_ANCHOR = "identity-smoke token idp-reset probe-resource"
PHONY_NEW = "identity-smoke token idp-reset probe-resource prove-passthrough"


def edit(path: Path, anchor: str, replacement: str, *, label: str) -> bool:
    """Apply one replacement, or report that it is already applied.

    Returns whether anything changed. Raises when the anchor is gone, because a
    patch script that cannot find its anchor has been handed a file it was not
    written against, and guessing is how a config file gets quietly corrupted.
    """
    text = path.read_text(encoding="utf-8")
    if replacement in text:
        print(f"  already applied: {label}")
        return False
    if anchor not in text:
        msg = (
            f"{path.name} does not contain the anchor for {label!r}. "
            f"Nothing has been written. Check that task 30 is on this branch."
        )
        raise SystemExit(msg)
    path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    print(f"  applied: {label}")
    return True


def main() -> int:
    makefile = ROOT / "Makefile"
    workflow = ROOT / ".github" / "workflows" / "ci.yml"

    for path in (makefile, workflow):
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 1

    print("Patching Makefile and CI for task 31.")
    edit(makefile, PHONY_ANCHOR, PHONY_NEW, label=".PHONY gains prove-passthrough")
    edit(makefile, MAKE_ANCHOR, MAKE_TARGET + MAKE_ANCHOR, label="make prove-passthrough")
    edit(workflow, CI_ANCHOR, CI_STEP, label="CI proves the test can fail")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
