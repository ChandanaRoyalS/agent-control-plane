"""The README states counts a reader will check. These are checked first.

The external review of v1.3.0 found the repository stating three different
decision-record counts. A count typed by hand is a count that drifts, so the
one the README states is compared with the directory, the way the site's
already is (`build_site.adr_count`).
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def decision_records() -> int:
    paths = (ROOT / "docs" / "decisions").glob("[0-9][0-9][0-9][0-9]-*.md")
    return sum(1 for path in paths if not path.name.startswith("0000-"))


def test_the_stated_decision_count_is_the_directory() -> None:
    stated = [int(n) for n in re.findall(r"(\d+) decision records", README)]

    assert stated, "the README no longer states a decision-record count"
    assert set(stated) == {decision_records()}


def test_no_other_decision_count_is_typed_by_hand() -> None:
    """The phrasings the previous counts used. One stated count, generated
    or checked, and every other mention says 'all of them'."""
    assert not re.search(r"All \d+ are in", README)
    assert not re.search(r"\d+ architecture decisions", README)


def test_the_stated_breakage_count_is_the_harnesses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Counted from the harnesses' own tables: every `MUTATIONS` entry, plus the
    broken readings the pre-dispatch proof runs against its search. The
    harnesses import one another by name, as they do when run, so `scripts/`
    goes on the path for the length of this test."""
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    total = 0
    for name in ("mutate_no_passthrough", "mutate_refusal", "mutate_result_cache"):
        total += len(importlib.import_module(name).MUTATIONS)
    proof = importlib.import_module("prove_predispatch")
    total += len(proof.MUTATIONS) + len(proof.BROKEN_READINGS)

    stated = re.search(r"(\d+) hand-picked breakages", README)
    assert stated is not None
    assert int(stated.group(1)) == total
