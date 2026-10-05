"""The committed schema baseline: each upstream's full tool definitions (ADR 0013).

Written by ``acp schemas capture`` and reviewed in git, so acknowledging a change is an
explicit human act; a self-updating baseline would adopt changes unseen. Full definitions
are stored and digests derived on demand, so ``git diff`` shows exactly what changed.
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
"""File format version; a mismatch is refused on load rather than misread as drift."""

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
        """A new snapshot with one upstream's catalogue replaced (never mutates)."""
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
        """This upstream's recorded tools, or ``None`` if never baselined (not "all tools new")."""
        entry = self.upstreams.get(upstream)
        return None if entry is None else entry.tools

    # -- persistence -------------------------------------------------------

    def save(self, path: Path) -> bool:
        """Write the snapshot atomically (temp file then rename).

        Returns:
            Whether the content changed; the timestamp is ignored, so an unchanged
            re-capture leaves the file alone.
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
        """Read a snapshot, or ``None`` if the file does not exist.

        Raises:
            ConfigurationError: The file is unreadable, malformed or the wrong version.
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
    """The file's content, or ``None`` if absent or unusable; used only to skip no-op writes."""
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _without_timestamp(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "captured_at"}
