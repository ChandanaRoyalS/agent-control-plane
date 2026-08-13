#!/usr/bin/env python3
"""Correct one tool name in the compose comment. Asserted, idempotent.

`docker-compose.yml` is a drift file, so it is never shipped whole. Task 55's
comment there named `mock-a__create-ticket`; the tool is `create_ticket`, with an
underscore. The comment has no behaviour, but a comment that contradicts the
policy file beside it is how the next person reintroduces the bug.

Separate from `patch_compose_task55.py` on purpose. That script matches on its
own inserted text to decide it has already run; editing it in place would make
it stop recognising an already-patched file and append the whole block a second
time. So the original keeps its shape for a fresh checkout, and this fixes the
one line on a tree that already has it.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

WRONG = "      # `policy.compose.yaml` holds `mock-a__create-ticket` for a person. This\n"
RIGHT = "      # `policy.compose.yaml` holds `mock-a__create_ticket` for a person. This\n"


def main() -> int:
    compose = ROOT / "docker-compose.yml"
    if not compose.exists():
        print(f"missing: {compose}", file=sys.stderr)
        return 1

    text = compose.read_text(encoding="utf-8")
    if RIGHT in text:
        print("  already applied: compose comment names create_ticket")
        return 0
    if WRONG not in text:
        msg = (
            "docker-compose.yml does not contain the task 55 comment. Nothing has "
            "been written. Check that patch_compose_task55.py has run on this tree."
        )
        raise SystemExit(msg)

    compose.write_text(text.replace(WRONG, RIGHT, 1), encoding="utf-8")
    print("  applied: compose comment names create_ticket")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
