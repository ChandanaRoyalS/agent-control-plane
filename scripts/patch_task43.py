#!/usr/bin/env python3
"""Wire the result-cache mutation harness into `make` and CI. Asserted, idempotent.

`Makefile` and `.github/workflows/ci.yml` are never shipped whole — they drift.
Every edit asserts its anchor first and aborts on the whole change if any is
missing, because a patch that half-applied would be worse than one that refused.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PHONY_ANCHOR = "prove-passthrough"
PHONY_NEW = "prove-passthrough prove-cache"

MAKE_ANCHOR = "probe-resource:  ## Measure what Keycloak does with RFC 8707's `resource`"
MAKE_HELP = "## Break the result cache's isolation on purpose, and check the test notices"
MAKE_TARGET = f"""prove-cache:  {MAKE_HELP}
\tuv run python scripts/mutate_result_cache.py

"""

CI_ANCHOR = """      - name: Prove the no-passthrough test can fail
        run: uv run python scripts/mutate_no_passthrough.py
"""

CI_STEP = """      - name: Prove the no-passthrough test can fail
        run: uv run python scripts/mutate_no_passthrough.py

      # The result cache's isolation has no symptom when it breaks: the leaked
      # answer is served, read, and recorded nowhere. So the test that guards it
      # is itself tested, on every pull request.
      - name: Prove the result-cache isolation test can fail
        run: uv run python scripts/mutate_result_cache.py
"""


def edit(path: Path, anchor: str, replacement: str, *, label: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if replacement in text:
        print(f"  already applied: {label}")
        return False
    if anchor not in text:
        msg = (
            f"{path.name} does not contain the anchor for {label!r}. Nothing has "
            f"been written. Check that task 31's patch is on this branch."
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

    print("Patching Makefile and CI for task 43.")
    edit(makefile, PHONY_ANCHOR, PHONY_NEW, label=".PHONY gains prove-cache")
    edit(makefile, MAKE_ANCHOR, MAKE_TARGET + MAKE_ANCHOR, label="make prove-cache")
    edit(workflow, CI_ANCHOR, CI_STEP, label="CI proves the isolation test can fail")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
