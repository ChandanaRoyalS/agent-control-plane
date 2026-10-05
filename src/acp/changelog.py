"""Parse the hand-written `CHANGELOG.md`.

Used by the release workflow (one release's notes) and by tests (the file agrees
with `acp.__version__`), so the parsing is testable Python rather than shell.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

HEADING: Final = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?:\s*-\s*(?P<date>\d{4}-\d{2}-\d{2}))?\s*$"
)
"""`## [1.0.0] - 2026-08-14`, date optional; anchored so bracketed prose is not a heading."""

UNRELEASED: Final = "Unreleased"

SEMVER: Final = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


@dataclass(frozen=True, slots=True)
class Release:
    """One section of the changelog."""

    version: str
    date: str | None
    body: str

    @property
    def released(self) -> bool:
        """False for `[Unreleased]`, which has no date and is not a version."""
        return self.version != UNRELEASED


def parse(text: str) -> tuple[Release, ...]:
    """Every `## [version]` section, in the order the file lists them."""
    found: list[Release] = []
    version: str | None = None
    date: str | None = None
    body: list[str] = []

    for line in text.splitlines():
        match = HEADING.match(line)
        if match is None:
            if version is not None:
                body.append(line)
            continue
        if version is not None:
            found.append(Release(version=version, date=date, body="\n".join(body).strip()))
        version = match.group("version")
        date = match.group("date")
        body = []

    if version is not None:
        found.append(Release(version=version, date=date, body="\n".join(body).strip()))

    return tuple(found)


def notes(text: str, version: str) -> str | None:
    """One release's body, or None if absent or empty; callers treat None as failure."""
    for release in parse(text):
        if release.version == version:
            return release.body or None
    return None


def order(version: str) -> tuple[int, int, int]:
    """A version as a sortable triple.

    Raises:
        ValueError: If `version` is not exactly three dot-separated integers.
    """
    match = SEMVER.match(version)
    if match is None:
        message = f"not a semantic version: {version!r}"
        raise ValueError(message)
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)
