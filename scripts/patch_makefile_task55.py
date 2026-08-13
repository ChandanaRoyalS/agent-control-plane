#!/usr/bin/env python3
"""Fix two Makefile targets that quietly did the wrong thing. Asserted, idempotent.

`Makefile` is a drift file and is never shipped whole. Both edits assert their
anchor first and the run aborts on the whole change if either is missing,
because a patch that half-applied would be worse than one that refused.

**1. `make token` has never worked in a login shell.**

    token:
        @uv run python scripts/keycloak_token.py $(or $(USER),alice)

`USER` is a standard POSIX environment variable, and make imports the
environment as make variables. So `$(USER)` is whoever is logged in, `$(or ...)`
finds it non-empty, and the target asks Keycloak for a token for a user that
does not exist in the realm — `invalid_grant: Invalid user credentials`. The
default is unreachable for anybody with a shell. Renamed to `ACP_USER`, which
belongs to this project and to nothing else.

**2. `make up` served whatever was last built.**

    up:
        docker compose up -d --wait gateway

Compose builds only when the image is absent, so a stack brought up after a
merge runs the code from before it. The symptom is a demo that behaves like an
old release, or eight identity checks failing against a fleet whose
introspection endpoint predates the script asking it — both observed, both
costing an hour before anybody suspected the image rather than the code.

This is the project's own recurring lesson pointed at its demo harness: an
under-specified thing does not fail, it silently runs different code. `--build`
is a few seconds when the layer cache is warm, and the alternative is trusting
everybody to remember `make image` first.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

USER_VAR_ANCHOR = """token:  ## Print an access token for alice (USER=bob for the other one)
\t@uv run python scripts/keycloak_token.py $(or $(USER),alice)
"""

USER_VAR_FIXED = """token:  ## Print an access token for alice (ACP_USER=bob for the other one)
\t@uv run python scripts/keycloak_token.py $(or $(ACP_USER),alice)
"""

UP_ANCHOR = """up:  ## Bring up the whole stack and wait until it is ready
\tdocker compose up -d --wait gateway
"""

UP_FIXED = """up:  ## Build, bring up the whole stack, and wait until it is ready
\t@# --build is not optional. Compose builds only when the image is absent, so
\t@# without it `make up` serves whatever was last built — which is how a stack
\t@# ends up running the code from before the merge you are trying to
\t@# demonstrate. Warm cache makes it a few seconds.
\tdocker compose up -d --build --wait gateway
"""


def edit(path: Path, anchor: str, replacement: str, *, label: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if replacement in text:
        print(f"  already applied: {label}")
        return False
    if anchor not in text:
        msg = (
            f"{path.name} does not contain the anchor for {label!r}. Nothing has "
            f"been written. Check that this branch is at task 55."
        )
        raise SystemExit(msg)
    path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    print(f"  applied: {label}")
    return True


def main() -> int:
    makefile = ROOT / "Makefile"
    if not makefile.exists():
        print(f"missing: {makefile}", file=sys.stderr)
        return 1

    print("Patching the Makefile for task 55's two harness bugs.")
    # Both anchors are checked before either is written, so a half-applied
    # Makefile is not a state this can produce.
    text = makefile.read_text(encoding="utf-8")
    for anchor, fixed, label in (
        (USER_VAR_ANCHOR, USER_VAR_FIXED, "make token"),
        (UP_ANCHOR, UP_FIXED, "make up"),
    ):
        if fixed not in text and anchor not in text:
            msg = f"Makefile has neither the old nor the new form of {label!r}. Nothing written."
            raise SystemExit(msg)

    edit(makefile, USER_VAR_ANCHOR, USER_VAR_FIXED, label="make token uses ACP_USER, not USER")
    edit(makefile, UP_ANCHOR, UP_FIXED, label="make up builds before it serves")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
