"""The captured surface against the running code's.

Separate from `test_surface.py` because this one needs `acp.cli`, and building
the real parser imports the MCP SDK. Keeping the pure tests in a file that does
not is what lets the comparison logic be exercised anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acp.cli import build_parser
from acp.surface import SURFACE_VERSION, compare, describe, render

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "docs" / "surface.json"

ENOUGH_SETTINGS = 40
ENOUGH_COMMANDS = 5


@pytest.fixture(scope="module")
def captured() -> dict[str, Any]:
    if not SNAPSHOT.exists():
        pytest.fail(f"{SNAPSHOT} is missing. Run: make surface-capture")
    loaded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        pytest.fail(f"{SNAPSHOT} is not an object")
    return loaded


def test_the_snapshot_is_not_empty(captured: dict[str, Any]) -> None:
    """LESSON 65 — assert the premise before asserting anything about it.

    A truncated or half-written snapshot would agree with a broken surface, and
    every test below it would pass while proving nothing. The thresholds are
    deliberately far below the real counts: this catches "the capture went
    wrong", not "somebody removed a setting", which is what the comparison is
    for.
    """
    assert len(captured["settings"]) >= ENOUGH_SETTINGS
    assert len(captured["commands"]) >= ENOUGH_COMMANDS
    assert captured["audit"]["fields"]


def test_the_snapshot_is_stamped_with_this_surface_version(
    captured: dict[str, Any],
) -> None:
    """A snapshot written under an older definition of "the surface" must not
    be read as agreement under a newer one."""
    assert captured["surface_version"] == SURFACE_VERSION


def test_the_public_surface_matches_what_was_captured(
    captured: dict[str, Any],
) -> None:
    """THE ONE THAT GATES A RELEASE.

    Nothing here decides whether a change is breaking; a person does, looking
    at the diff. What this removes is the case where nobody looks at all.
    """
    differences = compare(captured, describe(build_parser()))
    assert not differences, (
        f"\n{render(differences)}\n\n"
        f"If this is intended, accept it with `make surface-capture` and "
        f"decide what it does to the version number (ADR 0058)."
    )


def test_every_command_in_the_snapshot_is_reachable_from_the_real_parser(
    captured: dict[str, Any],
) -> None:
    """A weaker claim than the one above, kept because it fails with a much
    more readable message when a whole command group disappears."""
    live = {str(row["path"]) for row in describe(build_parser())["commands"]}
    recorded = {str(row["path"]) for row in captured["commands"]}
    assert live, "the running parser produced no commands at all"
    assert recorded <= live
