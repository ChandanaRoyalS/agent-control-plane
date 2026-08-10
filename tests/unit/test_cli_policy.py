"""Tests for `acp policy explain` (task 36)."""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.cli import build_parser, main

POLICY = """\
rules:
  - name: deny-delete
    effect: deny
    tools: [mock-a__delete]
  - name: allow-alice-search
    effect: allow
    subjects: [alice]
    tools: [mock-a__search]
  - name: allow-agent-list
    effect: allow
    actors: [reporting-agent]
    tools: [mock-a__list]
"""


def _policy_file(tmp_path: Path) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return str(path)


def test_explain_is_registered() -> None:
    args = build_parser().parse_args(
        ["policy", "explain", "--policy", "p.yaml", "--subject", "a", "--tool", "t"]
    )
    assert args.command == "policy"
    assert args.policy_command == "explain"


def test_allowed_prints_allow_and_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            _policy_file(tmp_path),
            "--subject",
            "alice",
            "--tool",
            "mock-a__search",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("ALLOW")
    assert "allow-alice-search" in out


def test_denied_prints_deny_and_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            _policy_file(tmp_path),
            "--subject",
            "alice",
            "--tool",
            "mock-a__delete",
        ]
    )
    out = capsys.readouterr().out
    assert code == 1
    assert out.startswith("DENY")
    assert "deny-delete" in out


def test_deny_by_default_names_no_rule(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            _policy_file(tmp_path),
            "--subject",
            "carol",
            "--tool",
            "mock-a__search",
        ]
    )
    out = capsys.readouterr().out
    assert code == 1
    assert "DENY" in out
    assert "deny default" in out


def test_actor_is_shown_and_matched(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            _policy_file(tmp_path),
            "--subject",
            "s",
            "--actor",
            "reporting-agent",
            "--tool",
            "mock-a__list",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "ALLOW" in out
    assert "reporting-agent" in out


def test_missing_policy_file_is_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            str(tmp_path / "nope.yaml"),
            "--subject",
            "alice",
            "--tool",
            "mock-a__search",
        ]
    )
    assert code == 2
    assert "could not load policy" in capsys.readouterr().err


def test_explain_with_a_matching_arg_allows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "rules:\n"
        "  - name: public-only\n"
        "    effect: allow\n"
        "    tools: [mock-a__read_document]\n"
        "    args:\n"
        "      doc_id: [public]\n",
        encoding="utf-8",
    )
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            str(policy),
            "--subject",
            "alice",
            "--tool",
            "mock-a__read_document",
            "--arg",
            "doc_id=public",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("ALLOW")
    assert "doc_id=public" in out


def test_explain_with_a_forbidden_arg_denies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "rules:\n"
        "  - name: public-only\n"
        "    effect: allow\n"
        "    tools: [mock-a__read_document]\n"
        "    args:\n"
        "      doc_id: [public]\n",
        encoding="utf-8",
    )
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            str(policy),
            "--subject",
            "alice",
            "--tool",
            "mock-a__read_document",
            "--arg",
            "doc_id=secret",
        ]
    )
    assert code == 1
    assert capsys.readouterr().out.startswith("DENY")


def test_explain_rejects_a_malformed_arg(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("rules:\n  - name: any\n    effect: allow\n", encoding="utf-8")
    code = main(
        [
            "policy",
            "explain",
            "--policy",
            str(policy),
            "--subject",
            "alice",
            "--tool",
            "t",
            "--arg",
            "no-equals-sign",
        ]
    )
    assert code == 2
    assert "KEY=VALUE" in capsys.readouterr().err
