"""Let test files contain literal token strings — one line in `pyproject.toml`.

`pyproject.toml` carries local edits (`uv add` put pyjwt there), so it is never
shipped whole — bug 26. This asserts its anchor before writing and is idempotent.

Why the change: ruff's S105/S106 flag any constant or argument whose *name*
suggests a credential. That is a good rule and it fires on every line of
`tests/unit/identity/test_exchange.py`, which is a test suite about tokens and
therefore full of strings called `access_token`. Suppressing it per line would
mean five `noqa` comments today and one more with every test added; suppressing
it for `tests/**` alongside the assertions and magic numbers already listed
there says the real thing, which is that a test fixture is not a secret.

Deliberately scoped to tests. In `src/**` the rule stays on, and the two places
that trip it there carry an explanatory `noqa` each.
"""

from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("pyproject.toml")

ANCHOR = """"tests/**" = [
    "S101",      # assert is the point of a test
    "PLR2004",   # magic numbers are fine in assertions
    "ARG",       # fixtures are often unused-by-name
]"""

REPLACEMENT = """"tests/**" = [
    "S101",      # assert is the point of a test
    "PLR2004",   # magic numbers are fine in assertions
    "ARG",       # fixtures are often unused-by-name
    "S105",      # a fixture named like a token is not a secret — see test_exchange
    "S106",      # ditto, as a keyword argument
]"""


def main() -> int:
    if not PATH.exists():
        sys.exit("patch aborted: pyproject.toml not found — run from the repository root")

    text = PATH.read_text(encoding="utf-8")
    if '"S105",      # a fixture named like a token' in text:
        print("pyproject.toml already patched; nothing to do.")
        return 0
    if ANCHOR not in text:
        sys.exit(
            "patch aborted: could not find the `tests/**` per-file-ignores block.\n"
            "Nothing was written. Add S105 and S106 to it by hand instead."
        )
    PATH.write_text(text.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print("pyproject.toml patched: S105/S106 ignored under tests/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
