"""Tests for `acp policy explain` and `acp policy simulate`."""

from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# `acp policy simulate` (task 38)
# ---------------------------------------------------------------------------


def _log_file(tmp_path: Path, *records: dict[str, object]) -> str:
    """A decision log in the shape `enforce_call` writes.

    Written by hand here rather than driven through the gateway, which the
    sandbox cannot import — `tests/unit/policy/test_record.py` closes that gap
    by round-tripping the *real* `enforce_call` through the *real* formatter.
    """
    defaults: dict[str, object] = {
        "event": "policy.allowed",
        "subject": "alice",
        "actor": None,
        "tool": "mock-a__search",
        "rule": "allow-alice-search",
        "decision": "allow",
        "argument_names": [],
    }
    path = tmp_path / "decisions.jsonl"
    path.write_text(
        "\n".join(json.dumps({**defaults, **record}) for record in records) + "\n",
        encoding="utf-8",
    )
    return str(path)


def test_simulate_is_registered() -> None:
    args = build_parser().parse_args(
        ["policy", "simulate", "--policy", "p.yaml", "--log", "d.jsonl"]
    )
    assert args.command == "policy"
    assert args.policy_command == "simulate"


def test_an_unchanged_policy_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "policy",
            "simulate",
            "--policy",
            _policy_file(tmp_path),
            "--log",
            _log_file(tmp_path, {}, {}),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "Replayed 2 recorded decisions" in out
    assert "No call would be decided differently." in out


def test_a_breaking_policy_exits_1_and_names_the_calls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 1, the same code `explain` uses for a denial — and pointedly not the
    usage error, so a red CI job says whether the policy or the command was
    wrong."""
    tightened = tmp_path / "tightened.yaml"
    tightened.write_text(
        "rules:\n  - name: no-search\n    effect: deny\n    tools: [mock-a__search]\n",
        encoding="utf-8",
    )

    code = main(
        [
            "policy",
            "simulate",
            "--policy",
            str(tightened),
            "--log",
            _log_file(tmp_path, {}),
        ]
    )

    out = capsys.readouterr().out
    assert code == 1
    assert "newly denied" in out
    assert "was: allow by allow-alice-search" in out
    assert "now: deny by no-search" in out


def test_show_caps_the_detail_but_never_the_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A log with ten thousand newly-denied calls must not bury the summary that
    said so."""
    tightened = tmp_path / "tightened.yaml"
    tightened.write_text(
        "rules:\n  - name: no-search\n    effect: deny\n    tools: [mock-a__search]\n",
        encoding="utf-8",
    )

    code = main(
        [
            "policy",
            "simulate",
            "--policy",
            str(tightened),
            "--log",
            _log_file(tmp_path, {}, {}, {}, {}, {}),
            "--show",
            "2",
        ]
    )

    out = capsys.readouterr().out
    assert code == 1
    assert "5 call(s) not proven unchanged" in out
    assert "... and 3 more" in out


def test_an_empty_log_says_so_rather_than_reporting_no_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """ "No changes" over a log with nothing in it is a dangerously reassuring
    way to describe having measured nothing."""
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")

    code = main(["policy", "simulate", "--policy", _policy_file(tmp_path), "--log", str(empty)])

    out = capsys.readouterr().out
    assert code == 0
    assert "No authorization decisions found" in out
    assert "No call would be decided differently" not in out


def test_unreadable_lines_are_reported_in_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """How much of the log was actually read is part of the answer to "is this
    edit safe"."""
    path = tmp_path / "partial.jsonl"
    path.write_text(
        json.dumps(
            {
                "event": "policy.allowed",
                "subject": "alice",
                "tool": "mock-a__search",
                "decision": "allow",
                "rule": "allow-alice-search",
                "argument_names": [],
            }
        )
        + '\n{"event": "policy.allowed", "sub\n',
        encoding="utf-8",
    )

    main(["policy", "simulate", "--policy", _policy_file(tmp_path), "--log", str(path)])

    assert "1 lines could not be read" in capsys.readouterr().out


def test_a_missing_log_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "policy",
            "simulate",
            "--policy",
            _policy_file(tmp_path),
            "--log",
            str(tmp_path / "nope.jsonl"),
        ]
    )

    assert code == 2
    assert "could not read the decision log" in capsys.readouterr().err
