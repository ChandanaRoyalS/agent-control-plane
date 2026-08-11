"""Loading the cacheable-tools table: every refusal, and why it is a refusal.

A malformed table is a boot failure with a filename, not a surprise on the first
request — the same discipline the policy and cost loaders follow. The one rule
that is not shared with them is the absence of a `default`, and it is the most
important line in the file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.exceptions import ConfigurationError
from acp.results.loader import load_cacheable
from acp.results.table import MAX_TTL_SECONDS


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "cache.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_table_is_read(tmp_path: Path) -> None:
    table = load_cacheable(write(tmp_path, "tools:\n  mock-a__search: 30\n  mock-b__search: 5.5\n"))

    assert table.ttl_for("mock-a__search") == 30.0
    assert table.ttl_for("mock-b__search") == 5.5


def test_an_unlisted_tool_is_not_cacheable(tmp_path: Path) -> None:
    """Opt-in, per tool. This is the assertion that stops a write being cached
    because somebody added a file."""
    table = load_cacheable(write(tmp_path, "tools:\n  mock-a__search: 30\n"))

    assert table.ttl_for("mock-a__create_ticket") is None


def test_not_cacheable_is_none_rather_than_zero(tmp_path: Path) -> None:
    """Distinct values, because a falsy check that conflates them eventually
    treats a configured tool as an unconfigured one."""
    table = load_cacheable(write(tmp_path, "tools:\n  mock-a__search: 0\n"))

    assert table.ttl_for("mock-a__search") == 0.0
    assert table.ttl_for("mock-b__search") is None


def test_there_is_no_way_to_make_everything_cacheable(tmp_path: Path) -> None:
    """The asymmetry with the cost table, and the reason for it.

    A `default` cost of 1.0 for an unlisted tool is a sensible guess about money.
    A default *ttl* for an unlisted tool would make every tool in the estate
    cacheable the moment somebody creates this file — including the writes. So
    `default` is not a key here, and a file that sets one gets it ignored rather
    than honoured.
    """
    table = load_cacheable(write(tmp_path, "default: 60\ntools:\n  mock-a__search: 30\n"))

    assert table.ttl_for("anything-else") is None
    assert table.names == ("mock-a__search",)


def test_an_empty_file_is_a_question_not_an_answer(tmp_path: Path) -> None:
    """No costs, or a truncated mount? Rather than guess, make the deployer say
    `tools: {}` to mean "cache nothing"."""
    with pytest.raises(ConfigurationError, match="empty"):
        load_cacheable(write(tmp_path, ""))


def test_an_explicit_empty_table_is_fine(tmp_path: Path) -> None:
    assert load_cacheable(write(tmp_path, "tools: {}\n")).names == ()


def test_a_missing_file_names_itself(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="cannot read"):
        load_cacheable(tmp_path / "absent.yaml")


def test_invalid_yaml_names_the_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not valid YAML"):
        load_cacheable(write(tmp_path, "tools:\n  - [unclosed\n"))


def test_a_document_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="mapping"):
        load_cacheable(write(tmp_path, "- mock-a__search\n"))


def test_tools_must_be_a_mapping(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="`tools` must be a mapping"):
        load_cacheable(write(tmp_path, "tools:\n  - mock-a__search\n"))


def test_a_ttl_must_be_a_number(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="must be a number"):
        load_cacheable(write(tmp_path, "tools:\n  mock-a__search: thirty\n"))


def test_a_boolean_ttl_is_refused(tmp_path: Path) -> None:
    """`bool` is a subclass of `int`, so `ttl: true` would otherwise silently
    mean one second — a value nobody typed and nobody would find."""
    with pytest.raises(ConfigurationError, match="must be a number"):
        load_cacheable(write(tmp_path, "tools:\n  mock-a__search: true\n"))


def test_a_negative_ttl_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="must not be negative"):
        load_cacheable(write(tmp_path, "tools:\n  mock-a__search: -5\n"))


def test_a_ttl_over_the_ceiling_is_refused_rather_than_clamped(tmp_path: Path) -> None:
    """Clamping would let a file ask for an hour and get five minutes with
    nobody told, so the deployment's stated intent and its actual behaviour would
    differ permanently and silently.

    The ceiling exists because a cached result outlives an upstream entitlement
    change by up to its ttl, and that exposure window belongs in code rather than
    in whatever somebody typed.
    """
    over = MAX_TTL_SECONDS + 1
    with pytest.raises(ConfigurationError, match="ceiling"):
        load_cacheable(write(tmp_path, f"tools:\n  mock-a__search: {over}\n"))


def test_the_ceiling_itself_is_allowed(tmp_path: Path) -> None:
    table = load_cacheable(write(tmp_path, f"tools:\n  mock-a__search: {MAX_TTL_SECONDS}\n"))

    assert table.ttl_for("mock-a__search") == MAX_TTL_SECONDS


def test_an_error_names_the_offending_entry(tmp_path: Path) -> None:
    """The account a human reads when a deploy fails. A bare "invalid" sends
    somebody to read the whole file."""
    path = write(tmp_path, "tools:\n  mock-a__search: 30\n  mock-b__summarize: nope\n")

    with pytest.raises(ConfigurationError) as caught:
        load_cacheable(path)

    assert "mock-b__summarize" in str(caught.value)
    assert str(path) in str(caught.value)
