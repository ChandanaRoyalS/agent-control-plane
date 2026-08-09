"""Unit tests for the policy loader.

Every failure path must raise ``ConfigurationError`` and name the file, because
these messages are read by a human at startup with the gateway refusing to run.
The one case that is *not* a failure — `rules: []` — is the deny-everything
policy, and it is kept distinct from a zero-byte file, which is treated as a
likely truncation and rejected with guidance rather than silently accepted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.exceptions import ConfigurationError
from acp.policy import Effect
from acp.policy.loader import load_policy


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_a_valid_policy(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "rules:\n  - name: allow-search\n    effect: allow\n    tools: [mock-a__search]\n",
    )
    policy = load_policy(path)
    assert len(policy.rules) == 1
    assert policy.rules[0].effect is Effect.ALLOW
    assert policy.rules[0].tools == ("mock-a__search",)


def test_rules_empty_is_a_valid_deny_everything_policy(tmp_path: Path) -> None:
    policy = load_policy(_write(tmp_path, "rules: []\n"))
    assert policy.rules == ()


def test_missing_file_is_fatal_and_names_the_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    with pytest.raises(ConfigurationError) as exc:
        load_policy(missing)
    assert "nope.yaml" in str(exc.value)


def test_empty_file_is_rejected_with_guidance(tmp_path: Path) -> None:
    """A zero-byte file is more likely a bad mount than an intended policy, so it
    is rejected — and the message tells the deployer how to say deny-everything
    on purpose."""
    with pytest.raises(ConfigurationError) as exc:
        load_policy(_write(tmp_path, ""))
    assert "rules: []" in str(exc.value)


def test_non_yaml_is_fatal_and_names_the_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError) as exc:
        load_policy(_write(tmp_path, "rules: [unterminated\n"))
    assert "policy.yaml" in str(exc.value)


def test_a_non_mapping_document_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError) as exc:
        load_policy(_write(tmp_path, "- just\n- a\n- list\n"))
    assert "mapping" in str(exc.value)


def test_a_schema_violation_names_the_file_and_says_invalid(tmp_path: Path) -> None:
    """A rule missing its effect is the deny-by-default guarantee reaching all
    the way out to the loader: the file fails to load rather than loading a rule
    that matches everything with no stated effect."""
    path = _write(tmp_path, "rules:\n  - name: no-effect\n")
    with pytest.raises(ConfigurationError) as exc:
        load_policy(path)
    message = str(exc.value)
    assert "policy.yaml" in message
    assert "is invalid" in message


def test_duplicate_names_fail_to_load(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "rules:\n"
        "  - name: allow-search\n"
        "    effect: allow\n"
        "  - name: allow-search\n"
        "    effect: deny\n",
    )
    with pytest.raises(ConfigurationError):
        load_policy(path)
