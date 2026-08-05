"""Tests for the CLI entry point."""

from __future__ import annotations

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
