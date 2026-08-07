"""Unit tests for the baseline file.

This file is committed to a repository and reviewed in a pull request, which
makes two of its properties matter more than they would for a cache: it must not
churn when nothing changed, and it must never be left half-written.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acp.exceptions import ConfigurationError
from acp.schema.snapshot import SNAPSHOT_VERSION, SchemaSnapshot
from acp.upstream.models import ListToolsResult


def catalogue(*names: str) -> ListToolsResult:
    return ListToolsResult.model_validate(
        {"tools": [{"name": name, "inputSchema": {"type": "object"}} for name in names]}
    )


def snapshot() -> SchemaSnapshot:
    return SchemaSnapshot.from_catalogues(
        {"mock-a": catalogue("search", "read_document"), "mock-b": catalogue("summarize")}
    )


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_a_saved_snapshot_loads_back_identically(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    original = snapshot()
    original.save(path)

    loaded = SchemaSnapshot.load(path)

    assert loaded is not None
    assert loaded.upstreams == original.upstreams


def test_an_absent_file_is_not_an_error(tmp_path: Path) -> None:
    """A system that has not been baselined yet is the state every new
    deployment starts in, and refusing to start over it would be absurd."""
    assert SchemaSnapshot.load(tmp_path / "nothing.json") is None


def test_tools_for_distinguishes_empty_from_absent() -> None:
    """An upstream with no entry has not lost its tools, it has never had a
    baseline. Collapsing the two is how adding a server to the config generates
    twenty meaningless alerts."""
    recorded = SchemaSnapshot.from_catalogues({"mock-a": catalogue()})

    assert recorded.tools_for("mock-a") == {}
    assert recorded.tools_for("mock-b") is None


def test_with_upstream_returns_a_new_object() -> None:
    """The detector accumulates one probe at a time, and a reader holding a
    snapshot must not watch it change underneath them."""
    before = SchemaSnapshot()
    after = before.with_upstream("mock-a", catalogue("search"))

    assert before.upstreams == {}
    assert set(after.upstreams) == {"mock-a"}


# ---------------------------------------------------------------------------
# Behaviour that exists because this file lives in git
# ---------------------------------------------------------------------------


def test_recapturing_an_unchanged_catalogue_does_not_touch_the_file(tmp_path: Path) -> None:
    """The timestamp is excluded from the comparison on purpose. A baseline that
    rewrites itself every run produces a diff every run, and a diff that is
    always non-empty is a diff nobody reads."""
    path = tmp_path / "baseline.json"
    assert snapshot().save(path) is True
    before = path.read_text(encoding="utf-8")

    assert snapshot().save(path) is False
    assert path.read_text(encoding="utf-8") == before


def test_a_real_change_does_rewrite_the_file(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    snapshot().save(path)

    changed = SchemaSnapshot.from_catalogues({"mock-a": catalogue("search", "exfiltrate")})

    assert changed.save(path) is True
    assert "exfiltrate" in path.read_text(encoding="utf-8")


def test_no_temporary_file_survives_a_successful_write(tmp_path: Path) -> None:
    """Written to a sibling and renamed, which is atomic on any POSIX
    filesystem. A snapshot truncated by a crash mid-write is a baseline that
    reports every tool in the system as removed the next time anything reads
    it."""
    path = tmp_path / "baseline.json"
    snapshot().save(path)

    assert [p.name for p in tmp_path.iterdir()] == ["baseline.json"]


def test_the_file_is_written_for_a_human_to_diff(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    snapshot().save(path)
    text = path.read_text(encoding="utf-8")

    assert text.endswith("\n")
    assert "\n  " in text, "not indented; a one-line JSON baseline cannot be reviewed"
    assert json.loads(text)["upstreams"]["mock-a"]["tools"]["search"]["inputSchema"]


def test_the_parent_directory_is_created(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "baseline.json"

    assert snapshot().save(path) is True
    assert path.exists()


# ---------------------------------------------------------------------------
# Refusing bad input
# ---------------------------------------------------------------------------


def test_unparseable_json_is_loud(tmp_path: Path) -> None:
    """Silently treating a corrupt baseline as an absent one would turn the
    detector into a thing that reports nothing, forever, with no indication
    why."""
    path = tmp_path / "baseline.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="not valid JSON"):
        SchemaSnapshot.load(path)


def test_a_future_format_version_is_refused(tmp_path: Path) -> None:
    """An old binary reading a newer file optimistically would see the added
    fields as things missing — which is to say as drift, reported loudly and
    wrongly, at exactly the moment somebody is mid-upgrade."""
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"version": SNAPSHOT_VERSION + 1, "upstreams": {}}), "utf-8")

    with pytest.raises(ConfigurationError, match="version"):
        SchemaSnapshot.load(path)


def test_a_structurally_wrong_document_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    body: dict[str, Any] = {"version": SNAPSHOT_VERSION, "upstreams": {"mock-a": ["not", "a map"]}}
    path.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="malformed"):
        SchemaSnapshot.load(path)


def test_an_unreadable_path_is_refused(tmp_path: Path) -> None:
    """A directory where a file should be. Distinct from "absent", and worth
    saying so rather than reporting the system as unbaselined."""
    (tmp_path / "baseline.json").mkdir()

    with pytest.raises(ConfigurationError, match="cannot read"):
        SchemaSnapshot.load(tmp_path / "baseline.json")


def test_a_corrupt_existing_file_does_not_block_replacing_it(tmp_path: Path) -> None:
    """Deliberately forgiving where `load` is strict: refusing to repair a
    corrupt baseline would be a strange way to handle the request to replace
    it."""
    path = tmp_path / "baseline.json"
    path.write_text("{not json", encoding="utf-8")

    assert snapshot().save(path) is True
    assert SchemaSnapshot.load(path) is not None
