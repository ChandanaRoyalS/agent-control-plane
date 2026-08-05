"""Tests for configuration loading.

Every test here asserts a *failure* is loud and names the file. That is the
whole point of the module: configuration errors are read by a human under
pressure, and "1 validation error for UpstreamConfig" with no filename is not
an error message, it is a puzzle.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.config import GatewaySettings, load_settings, load_upstreams
from acp.exceptions import ConfigurationError

VALID = """
upstreams:
  - name: mock-a
    url: http://localhost:9101/mcp
  - name: mock-b
    url: http://localhost:9102/mcp
    read_timeout: 15.0
"""


def write(tmp_path: Path, text: str, name: str = "upstreams.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_file_loads_both_upstreams(tmp_path: Path) -> None:
    configs = load_upstreams(write(tmp_path, VALID))

    assert [c.name for c in configs] == ["mock-a", "mock-b"]
    assert configs[1].read_timeout == 15.0


def test_omitted_fields_fall_back_to_defaults(tmp_path: Path) -> None:
    configs = load_upstreams(write(tmp_path, VALID))

    assert configs[0].read_timeout == 30.0
    assert configs[0].connect_timeout == 3.0


# ---------------------------------------------------------------------------
# Every failure names the file
# ---------------------------------------------------------------------------


def test_missing_file_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="cannot read upstreams file"):
        load_upstreams(tmp_path / "does-not-exist.yaml")


def test_invalid_yaml_is_reported_as_yaml(tmp_path: Path) -> None:
    path = write(tmp_path, "upstreams: [unclosed")

    with pytest.raises(ConfigurationError, match="not valid YAML") as exc_info:
        load_upstreams(path)

    assert "upstreams.yaml" in exc_info.value.message


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="is empty"):
        load_upstreams(write(tmp_path, ""))


def test_missing_upstreams_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="`upstreams` key"):
        load_upstreams(write(tmp_path, "servers: []"))


def test_upstreams_must_be_a_list(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="must be a list"):
        load_upstreams(write(tmp_path, "upstreams:\n  mock-a: http://x/mcp"))


def test_non_mapping_entry_is_rejected_with_its_index(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="upstream #0"):
        load_upstreams(write(tmp_path, "upstreams:\n  - just-a-string"))


def test_invalid_entry_is_reported_by_name(tmp_path: Path) -> None:
    """The name is far more useful than the index when a file has twenty entries."""
    text = "upstreams:\n  - name: mock-a\n    url: ftp://nope\n"

    with pytest.raises(ConfigurationError, match="'mock-a'") as exc_info:
        load_upstreams(write(tmp_path, text))

    assert "upstreams.yaml" in exc_info.value.message


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    """A typo must fail rather than silently do nothing.

    `read_timout` looks close enough to be missed in review, and the failure it
    causes — the default timeout applying instead of the configured one — would
    only surface as unexplained latency much later.
    """
    text = "upstreams:\n  - name: mock-a\n    url: http://x/mcp\n    read_timout: 5\n"

    with pytest.raises(ConfigurationError, match="invalid"):
        load_upstreams(write(tmp_path, text))


def test_duplicate_names_are_rejected(tmp_path: Path) -> None:
    """Ambiguous names would make `mock-a__search` resolve to whichever was last."""
    text = (
        "upstreams:\n"
        "  - name: mock-a\n    url: http://x/mcp\n"
        "  - name: mock-a\n    url: http://y/mcp\n"
    )

    with pytest.raises(ConfigurationError, match="appears more than once"):
        load_upstreams(write(tmp_path, text))


def test_an_empty_upstream_list_is_allowed(tmp_path: Path) -> None:
    """A gateway with nothing attached is useless but not misconfigured.

    Refusing to start here would break the legitimate case of bringing the
    gateway up before its upstreams exist.
    """
    assert load_upstreams(write(tmp_path, "upstreams: []")) == []


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_defaults_bind_loopback_only() -> None:
    """A gateway that binds every interface by accident is exposed before
    anyone decided it should be."""
    settings = GatewaySettings(_env_file=None)  # type: ignore[call-arg]

    assert settings.host == "127.0.0.1"
    assert settings.allowed_hosts == ["127.0.0.1", "localhost"]


def test_environment_overrides_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACP_PORT", "9999")
    monkeypatch.setenv("ACP_LOG_LEVEL", "DEBUG")

    settings = GatewaySettings(_env_file=None)  # type: ignore[call-arg]

    assert settings.port == 9999
    assert settings.log_level == "DEBUG"


def test_allowed_hosts_can_be_set_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Required for any deployment behind a real hostname — see task 9."""
    monkeypatch.setenv("ACP_ALLOWED_HOSTS", '["gateway.internal", "localhost"]')

    settings = GatewaySettings(_env_file=None)  # type: ignore[call-arg]

    assert settings.allowed_hosts == ["gateway.internal", "localhost"]


def test_out_of_range_port_fails_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACP_PORT", "70000")

    with pytest.raises(ConfigurationError, match="invalid gateway configuration"):
        load_settings(_env_file=None)


def test_unknown_setting_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigurationError):
        load_settings(_env_file=None, nonsense=True)
