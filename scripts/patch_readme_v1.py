#!/usr/bin/env python3
"""Bring the README up to v1.0.0: the counts, the roadmap, the published image.

    python3 scripts/patch_readme_v1.py

Four anchors, and **all four are checked before any is written** (rule 2d).

Lesson 67 for the second time on the same file. When it was rewritten in task
65 the badge had pointed at `USERNAME` since the day the repository was created
and the roadmap called five finished phases "planned". Six merges later the
counts are stale again and the roadmap still says the release is in progress --
while a tagged, published, anonymously-pullable image sits on ghcr.

**Nothing in CI checks the README's numbers**, which is why they are the ones
that rot. The counts here are hand-maintained and will go stale again; what
stops that becoming a pattern is `docs/surface.json` and the ADR index test,
which cover the two facts a reader is most likely to act on.

The roadmap row is deliberately NOT marked `complete`. v1.0.0 is released and
the write-up is not finished, and a row claiming otherwise would be the exact
failure this patch exists to fix.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path("README.md")

MARKER = "1,893 tests"

# --- 1. the badge row ---------------------------------------------------------

REPO = "chandanaroyal719-bot/agent-control-plane"

ANCHOR_BADGE = (
    f"[![CI](https://github.com/{REPO}/actions/workflows/ci.yml/badge.svg)]"
    f"(https://github.com/{REPO}/actions/workflows/ci.yml)\n"
)

REPLACEMENT_BADGE = ANCHOR_BADGE.rstrip("\n") + (
    f"\n[![release](https://img.shields.io/github/v/release/{REPO}?label=release)]"
    f"(https://github.com/{REPO}/releases/latest)\n"
)

# --- 2. the counts ------------------------------------------------------------

ANCHOR_COUNTS = (
    "**1,766 tests · 94% coverage · 57 architecture decisions · 4 mutation "
    "harnesses\nproving 16 deliberate breakages are caught**\n"
)

REPLACEMENT_COUNTS = (
    "**1,893 tests · 94% coverage · 58 architecture decisions · 4 mutation "
    "harnesses\nproving 16 deliberate breakages are caught**\n"
)

# --- 3. the roadmap's last row ------------------------------------------------

ANCHOR_ROADMAP = "| 10 · Release | in progress | v1.0.0, architecture docs, write-up |\n"

REPLACEMENT_ROADMAP = (
    "| 10 · Release | **v1.0.0 released** | Tagged and published to ghcr; "
    "architecture map, an index of all 58 decisions, and a machine-checked "
    "release surface. The write-up and the demo recording are outstanding |\n"
)

# --- 4. the published image ---------------------------------------------------

ANCHOR_IMAGE = "Then look at it: the MCP endpoint on `:8080`, metrics, health and schema drift\n"

IMAGE = f"""Compose builds from source. The **released image** is published on every tag,
and is the one the release workflow verified before it pushed -- built without
the mock upstreams and asserted to be, running as uid 10001:

```bash
docker pull ghcr.io/{REPO}:1.0.0
docker run --rm --entrypoint python \\
  ghcr.io/{REPO}:1.0.0 \\
  -c "import acp; print(acp.__version__)"
```

Pinned deliberately. `:latest` is published because refusing to publish it does
not make anybody pin -- it makes them write a worse `docker run` -- and this
file never uses it.

"""


def main() -> int:
    path = ROOT / TARGET
    print("Bringing the README up to v1.0.0.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if MARKER in text:
        print("  already applied")
        print("done.")
        return 0

    edits = (
        ("the CI badge", ANCHOR_BADGE, REPLACEMENT_BADGE),
        ("the counts line", ANCHOR_COUNTS, REPLACEMENT_COUNTS),
        ("the roadmap's release row", ANCHOR_ROADMAP, REPLACEMENT_ROADMAP),
        ("the quickstart's 'Then look at it' line", ANCHOR_IMAGE, IMAGE + ANCHOR_IMAGE),
    )

    # Rule 2d. A partial application would leave a README claiming one thing in
    # its header and another in its roadmap, which is worse than either.
    missing = [name for name, anchor, _ in edits if anchor not in text]
    if missing:
        msg = (
            f"{TARGET} is missing {', '.join(missing)}, and does not already "
            f"have the change. NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    for name, anchor, replacement in edits:
        text = text.replace(anchor, replacement, 1)
        print(f"  applied: {name}")

    path.write_text(text, encoding="utf-8")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
