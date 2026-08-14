"""Every relative link in the documentation points at something — task 65.

**This exists because moving one file broke fourteen links at once.**

`docs/ARCHITECTURE.md` was carved out of `README.md` so a stranger could still
understand the project in five minutes. Every link in the moved text was
written relative to the repository root, and the new file lives one directory
down — so `docs/decisions/0013-...` became `docs/docs/decisions/0013-...` and
resolved to nothing.

Nothing errors. Markdown renders a dead link exactly as well as a live one, and
the only symptom is a reader clicking a citation on the front page of the
project and landing on GitHub's 404. **For a repository whose whole argument is
that its claims are checkable, a citation that goes nowhere is the worst
possible small bug.**

Anchors (`#section`) and external URLs are not checked. An anchor needs a
Markdown renderer's slug rules to verify and would fail on punctuation this
project uses freely; an external URL needs the network, and a test that needs
the network fails for reasons that are not about this repository.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]

LINK = re.compile(r"\[(?P<label>[^\]]+)\]\((?P<target>[^)\s]+)\)")

SKIP = ("http://", "https://", "#", "mailto:")

DOCUMENTS = sorted(
    path
    for path in ROOT.rglob("*.md")
    if ".venv" not in path.parts and "node_modules" not in path.parts
)


def test_there_are_documents_to_check() -> None:
    """The premise. A glob that matched nothing would make every assertion below
    vacuous and passing — which is the failure mode of any test that guards
    against absence."""
    assert len(DOCUMENTS) > 50


@pytest.mark.parametrize("document", DOCUMENTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_relative_link_resolves(document: Path) -> None:
    """A link is a claim that something is there."""
    broken = [
        f"[{match['label']}]({match['target']})"
        for match in LINK.finditer(document.read_text(encoding="utf-8"))
        if not match["target"].startswith(SKIP)
        and not (document.parent / match["target"].split("#", 1)[0]).exists()
    ]
    assert not broken, f"{document.relative_to(ROOT)} links to nothing: {broken}"
