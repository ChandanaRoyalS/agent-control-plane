"""Every decision is in the index, and the index invents none — task 66.

*"Every decision you had to think about, ten minutes each. The highest
return-per-minute artifact in the repository when someone asks 'why that
way.'"*

Fifty-seven of them is past the point where a reader can find the right one by
listing a directory, so there is an index. And **an index is a hand-maintained
list, which is a list somebody forgets to extend** — the exact failure that
shipped six times as an unwired control (ADR 0055) and once as fourteen broken
links (task 65).

So this checks both directions. A new ADR that nobody indexed fails; an index
entry pointing at a file that was renamed fails. The relative links themselves
are covered by `test_links.py`; what this adds is *completeness*, which no link
checker can see — a missing entry links to nothing and therefore breaks nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DECISIONS = ROOT / "docs" / "decisions"
INDEX = DECISIONS / "README.md"

TEMPLATE = "0000-template.md"

NUMBERED = re.compile(r"^\d{4}-.+\.md$")


def decisions() -> set[str]:
    """Every ADR file, template excluded — it decides nothing."""
    return {
        path.name
        for path in DECISIONS.glob("*.md")
        if NUMBERED.match(path.name) and path.name != TEMPLATE
    }


def indexed() -> set[str]:
    """Every ADR the index links to, template excluded.

    The index links the template from its "format" section, which is a
    legitimate link and not a decision — and this test caught that on its first
    run, which is a small demonstration of the thing it exists for.
    """
    text = INDEX.read_text(encoding="utf-8")
    found = set(re.findall(r"\]\((\d{4}-[^)]+\.md)\)", text))
    return found - {TEMPLATE}


def test_there_are_decisions_to_index() -> None:
    """The premise, asserted first. A glob that matched nothing would make both
    tests below vacuous and passing — which is how a test that guards against
    absence fails silently."""
    assert len(decisions()) > 50


def test_every_decision_appears_in_the_index() -> None:
    """A decision nobody indexed is a decision nobody finds. It is also the
    likeliest one to be missing, because writing an ADR and updating an index
    are two acts and only the first feels like the work."""
    missing = sorted(decisions() - indexed())
    assert not missing, f"written but not indexed: {missing}"


def test_the_index_names_no_decision_that_does_not_exist() -> None:
    """The other direction. A renamed file leaves an entry describing something
    that is not there — and a reader trusts an index more than a directory
    listing, which is what makes a wrong one worse than none."""
    invented = sorted(indexed() - decisions())
    assert not invented, f"indexed but not written: {invented}"


def test_the_index_is_not_merely_a_list_of_filenames() -> None:
    """Each entry has to say what was DECIDED. The filenames already say the
    titles; an index that repeats them adds a click and no information."""
    text = INDEX.read_text(encoding="utf-8")
    rows = re.findall(r"\|\s*\[(\d{4})\]\([^)]+\)\s*\|\s*([^|]+)\|", text)
    assert len(rows) >= len(decisions())
    for number, summary in rows:
        assert len(summary.strip()) > 25, f"{number} is indexed without a summary"
