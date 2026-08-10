"""Unit tests for loading a cost table from YAML."""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.budget import load_costs
from acp.exceptions import ConfigurationError


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "costs.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_costs_and_default(tmp_path: Path) -> None:
    path = _write(
        tmp_path, "default: 2.0\ncosts:\n  mock-a__search: 5\n  mock-b__summarize: 10.5\n"
    )
    table = load_costs(path)
    assert table.cost_of("mock-a__search") == 5.0
    assert table.cost_of("mock-b__summarize") == 10.5
    assert table.cost_of("unlisted") == 2.0


def test_default_defaults_to_one_when_omitted(tmp_path: Path) -> None:
    path = _write(tmp_path, "costs:\n  mock-a__search: 5\n")
    assert load_costs(path).cost_of("unlisted") == 1.0


def test_an_empty_costs_map_is_allowed(tmp_path: Path) -> None:
    """`costs: {}` means 'no weighting' — every tool costs the default."""
    path = _write(tmp_path, "costs: {}\n")
    assert load_costs(path).cost_of("anything") == 1.0


def test_a_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="cannot read costs file"):
        load_costs(tmp_path / "nope.yaml")


def test_an_empty_file_is_rejected(tmp_path: Path) -> None:
    """Ambiguous between 'no costs' and a truncated mount — make it explicit."""
    path = _write(tmp_path, "")
    with pytest.raises(ConfigurationError, match="is empty"):
        load_costs(path)


def test_invalid_yaml_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, "costs: [this is not: a mapping\n")
    with pytest.raises(ConfigurationError, match="not valid YAML"):
        load_costs(path)


def test_a_non_numeric_cost_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, "costs:\n  mock-a__search: expensive\n")
    with pytest.raises(ConfigurationError, match="must be a number"):
        load_costs(path)


def test_a_negative_cost_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, "costs:\n  mock-a__search: -1\n")
    with pytest.raises(ConfigurationError, match="must not be negative"):
        load_costs(path)


def test_a_boolean_cost_is_rejected(tmp_path: Path) -> None:
    """YAML `true` is not a number, even though Python bool is an int subclass."""
    path = _write(tmp_path, "costs:\n  mock-a__search: true\n")
    with pytest.raises(ConfigurationError, match="must be a number"):
        load_costs(path)
