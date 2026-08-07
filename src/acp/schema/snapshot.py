"""The recorded state of every upstream's catalogue — the thing drift is *from*.

A snapshot is a JSON document mapping each upstream to the tool definitions it
was last known to expose. It is written by ``acp schemas capture``, committed to
the repository, and reviewed in a pull request like any other change.

**Why a committed file rather than a table or an in-memory baseline.** An
in-memory baseline is populated by the first response the process sees, which
means a change made during a deploy window is adopted as normal before anyone
could notice it — the detector would be certifying whatever it happened to start
against. A database would work and would cost a dependency, a migration and a
backup story for a document measured in kilobytes. A file in git gets review,
history, blame and rollback for free, and makes acknowledging a change an
explicit human act with a name attached to it. That last property is the whole
point: a baseline that updates itself is not a baseline, it is a log of the most
recent state, and it can never tell you that something happened while you were
not looking.

**Definitions are stored, digests are not.** The file holds each tool's full wire
definition; every fingerprint is derived on demand. Storing a digest next to the
thing it digests is two sources of truth that can disagree, and the disagreement
is silent. Keeping the definitions also makes ``git diff`` on this file show
exactly what changed, in the upstream's own words, which is the review workflow
this design is built around.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from acp.exceptions import ConfigurationError
from acp.schema.fingerprint import definitions_of, fingerprint_catalogue
from acp.upstream.models import ListToolsResult

SNAPSHOT_VERSION = 1
"""Format version of the file itself.

Checked on load and refused on mismatch rather than parsed optimistically. A
future version that adds a field would otherwise be read by an old binary as a
catalogue with things missing — which is to say, as drift, reported loudly and
wrongly at exactly the moment someone is mid-upgrade.
"""

DEFAULT_BASELINE_PATH = Path("config/schema-baseline.json")


class UpstreamSnapshot(BaseModel):
    """One upstream's recorded catalogue."""

    model_config = ConfigDict(extra="forbid")

    tools: dict[str, dict[str, Any]] = Field(default_factory=dict)
    """Tool name to the definition the upstream sent, in wire form."""

    @property
    def fingerprint(self) -> str:
        return fingerprint_catalogue(self.tools)


class SchemaSnapshot(BaseModel):
    """Every upstream's recorded catalogue, plus when it was recorded."""

    model_config = ConfigDict(extra="forbid")

    version: int = SNAPSHOT_VERSION
    captured_at: str | None = None
    upstreams: dict[str, UpstreamSnapshot] = Field(default_factory=dict)

    # -- building ----------------------------------------------------------

    @classmethod
    def from_catalogues(cls, catalogues: Mapping[str, ListToolsResult]) -> Self:
        return cls(
            captured_at=datetime.now(UTC).isoformat(timespec="seconds"),
            upstreams={
                name: UpstreamSnapshot(tools=definitions_of(result.tools))
                for name, result in catalogues.items()
            },
        )

    def with_upstream(self, name: str, result: ListToolsResult) -> Self:
        """A copy with one upstream's catalogue replaced.

        Used by the detector, which learns about upstreams one probe at a time
        rather than all at once. Returns a new object rather than mutating: a
        reader holding a snapshot must not watch it change underneath them.
        """
        return self.model_copy(
            update={
                "upstreams": {
                    **self.upstreams,
                    name: UpstreamSnapshot(tools=definitions_of(result.tools)),
                }
            }
        )

    # -- reading -----------------------------------------------------------

    def tools_for(self, upstream: str) -> dict[str, dict[str, Any]] | None:
        """This upstream's recorded tools, or ``None`` if it was never recorded.

        The distinction is load-bearing. An upstream with no entry has not lost
        its tools, it has never had a baseline — and reporting twenty "new tool"
        events the first time a server is added to the config would train
        everybody to ignore the alert that matters.
        """
        entry = self.upstreams.get(upstream)
        return None if entry is None else entry.tools

    # -- persistence -------------------------------------------------------

    def save(self, path: Path) -> bool:
        """Write the snapshot. Returns whether the file's content actually changed.

        Two details that are not incidental.

        The timestamp is excluded from the comparison, so re-capturing an
        unchanged catalogue leaves the file — and ``git status`` — alone. A
        baseline that rewrites itself with a new timestamp every run produces a
        diff on every run, and a diff that is always non-empty is a diff nobody
        reads.

        The write goes to a temporary file in the same directory and is then
        renamed, which is atomic on any POSIX filesystem. A snapshot truncated by
        a crash mid-write is a baseline that reports every tool in the system as
        removed the next time anything reads it.
        """
        payload = self.model_dump(mode="json")
        existing = _read_json(path)
        if existing is not None and _without_timestamp(existing) == _without_timestamp(payload):
            return False

        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
        return True

    @classmethod
    def load(cls, path: Path) -> Self | None:
        """Read a snapshot. ``None`` when the file does not exist.

        A missing file is not an error — it is a system that has not been
        baselined yet, which is the state every new deployment starts in. A file
        that exists and cannot be read *is* an error, and a loud one: silently
        treating a corrupt baseline as an absent one would turn a detector into a
        thing that reports nothing, forever, with no indication why.
        """
        raw = _read_text(path)
        if raw is None:
            return None

        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            msg = f"schema baseline {str(path)!r} is not valid JSON: {exc}"
            raise ConfigurationError(msg) from exc

        version = document.get("version") if isinstance(document, dict) else None
        if version != SNAPSHOT_VERSION:
            msg = (
                f"schema baseline {str(path)!r} is version {version!r}, "
                f"this build reads version {SNAPSHOT_VERSION}"
            )
            raise ConfigurationError(msg)

        try:
            return cls.model_validate(document)
        except ValidationError as exc:
            msg = f"schema baseline {str(path)!r} is malformed: {exc}"
            raise ConfigurationError(msg) from exc


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        msg = f"cannot read schema baseline {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc


def _read_json(path: Path) -> dict[str, Any] | None:
    """The file's current content, or ``None`` if it is absent or unusable.

    Deliberately forgiving where :meth:`SchemaSnapshot.load` is strict, because
    this is only ever used to decide whether a write can be skipped. An
    unreadable existing file means "write it", not "raise" — refusing to repair
    a corrupt baseline would be a strange way to handle the request to replace
    it.
    """
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _without_timestamp(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "captured_at"}
