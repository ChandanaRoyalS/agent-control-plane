"""Tests for the CLI entry point."""

from __future__ import annotations

from typing import Any

import pytest

from acp import __version__
from acp.cli import build_parser, main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help_and_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "usage:" in capsys.readouterr().err


def test_parser_builds() -> None:
    assert build_parser().prog == "acp"


def test_probe_and_call_are_registered() -> None:
    parser = build_parser()

    assert parser.parse_args(["probe", "--url", "http://x/mcp"]).command == "probe"
    assert parser.parse_args(["call", "--url", "http://x/mcp", "--tool", "t"]).command == "call"


def test_invalid_upstream_name_exits_2_without_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Config errors are user mistakes, not crashes."""
    exit_code = main(["probe", "--url", "http://x/mcp", "--name", "Bad_Name"])

    assert exit_code == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_non_http_url_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["probe", "--url", "ftp://x/mcp"]) == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_malformed_args_json_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["call", "--url", "http://x/mcp", "--tool", "t", "--args", "{not json"])

    assert exit_code == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_args_must_be_a_json_object(capsys: pytest.CaptureFixture[str]) -> None:
    """A JSON array parses fine but is not a valid arguments payload."""
    exit_code = main(["call", "--url", "http://x/mcp", "--tool", "t", "--args", "[1, 2]"])

    assert exit_code == 2
    assert "must be a JSON object" in capsys.readouterr().err


def test_unreachable_upstream_exits_1_with_a_structured_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An upstream being down is expected, so it must not produce a stack trace.

    Port 9 is the discard port and is reliably closed, so this exercises the
    real connection-failure path without depending on any external service.
    """
    exit_code = main(["probe", "--url", "http://127.0.0.1:9/mcp", "--connect-timeout", "0.05"])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert '"recoverable": true' in err


# ---------------------------------------------------------------------------
# `acp schemas` (task 20)
# ---------------------------------------------------------------------------


def test_schemas_has_two_verbs() -> None:
    """Two, not one. A command that both reports drift and records it as the
    new normal can only ever tell you something once, and tells the next person
    nothing at all — see ADR 0013."""
    parser = build_parser()

    captured = parser.parse_args(["schemas", "capture"])
    checked = parser.parse_args(["schemas", "check"])

    assert (captured.command, captured.schemas_command) == ("schemas", "capture")
    assert (checked.command, checked.schemas_command) == ("schemas", "check")


def test_only_capture_can_be_told_to_ignore_a_dead_upstream() -> None:
    """`check` has no --allow-partial on purpose. "I could not tell" and
    "nothing changed" are different answers, and a checker that returns the
    second when it means the first is worse than no checker."""
    parser = build_parser()

    assert parser.parse_args(["schemas", "capture"]).allow_partial is False
    assert not hasattr(parser.parse_args(["schemas", "check"]), "allow_partial")


def test_schemas_without_a_verb_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["schemas"])

    assert "capture" in capsys.readouterr().out


def test_check_without_a_baseline_says_what_to_run(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Read before any network call, so a missing baseline costs no round
    trips and the message names the command that fixes it."""
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("upstreams: []\n", encoding="utf-8")

    exit_code = main(
        [
            "schemas",
            "check",
            "--upstreams-file",
            str(upstreams),
            "--baseline",
            str(tmp_path / "absent.json"),
        ]
    )

    assert exit_code == 2
    assert "acp schemas capture" in capsys.readouterr().err


def test_capture_writes_a_baseline_it_can_then_check(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The round trip, with no upstreams configured — enough to exercise
    writing, reading back and reporting no drift."""
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("upstreams: []\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    argv = ["--upstreams-file", str(upstreams), "--baseline", str(baseline)]

    assert main(["schemas", "capture", *argv]) == 0
    assert baseline.exists()

    capsys.readouterr()
    assert main(["schemas", "check", *argv]) == 0
    assert "no drift" in capsys.readouterr().out
