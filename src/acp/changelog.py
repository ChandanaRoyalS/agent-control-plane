"""Reading `CHANGELOG.md` as data.

Task 67. The release workflow needs one release's notes to put in a GitHub
release, and the test suite needs to check that the file agrees with
`acp.__version__`. Both are parsing, both are easy to get subtly wrong, and
neither should be a shell pipeline inside a YAML file where it cannot be tested.

**Why a changelog is parsed rather than generated.** `git log` is a record of
commits, and a commit is a unit of work rather than a unit of change: "fix
review comments" is in the history and belongs nowhere near a release note. A
changelog written by a person says what a *reader* has to do differently, which
is the only question a release note answers.

So it is hand-written — and therefore it can be wrong, out of date, or missing
the version being tagged. That is what makes it worth testing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

HEADING: Final = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?:\s*-\s*(?P<date>\d{4}-\d{2}-\d{2}))?\s*$"
)
"""`## [1.0.0] - 2026-08-14`, with the date optional so `[Unreleased]` parses.

Anchored at both ends: a line that merely *contains* something bracket-shaped
is prose, and treating it as a heading would silently split one release's notes
in half.
"""

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
    """One release's body, or None when the changelog does not describe it.

    None rather than an empty string, and the caller is expected to treat it as
    a failure. A release published with empty notes is indistinguishable from
    one whose notes were lost, and the workflow refuses rather than guessing.
    """
    for release in parse(text):
        if release.version == version:
            return release.body or None
    return None


def order(version: str) -> tuple[int, int, int]:
    """A version as a sortable triple.

    Raises `ValueError` on anything that is not exactly three integers, which
    is what makes the test for descending order also a test that every heading
    is a real version.
    """
    match = SEMVER.match(version)
    if match is None:
        message = f"not a semantic version: {version!r}"
        raise ValueError(message)
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)
