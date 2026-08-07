"""Tests for configuration loading.

Every test here asserts a *failure* is loud and names the file. That is the
whole point of the module: configuration errors are read by a human under
pressure, and "1 validation error for UpstreamConfig" with no filename is not
an error message, it is a puzzle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from acp.config import (
    GatewaySettings,
    allowed_hosts_for,
    load_issuers,
    load_settings,
    load_upstreams,
)
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


# ---------------------------------------------------------------------------
# Host allow-list expansion
# ---------------------------------------------------------------------------


def test_allow_list_gains_the_port_qualified_form() -> None:
    """The bug the whole test suite missed until a real client connected.

    A client reaching `http://127.0.0.1:8080/mcp` sends `Host: 127.0.0.1:8080`.
    A bare `127.0.0.1` in the allow-list does not match it, and the SDK answers
    421 Misdirected Request. The tests never caught this because they connect on
    the default port, where the Host header carries no port suffix.
    """
    assert allowed_hosts_for(["127.0.0.1", "localhost"], 8080) == [
        "127.0.0.1",
        "127.0.0.1:8080",
        "localhost",
        "localhost:8080",
    ]


def test_explicit_ports_are_left_alone() -> None:
    """An operator who wrote `gateway.internal:443` meant exactly that."""
    assert allowed_hosts_for(["gateway.internal:443"], 8080) == ["gateway.internal:443"]


def test_expansion_is_idempotent_in_effect() -> None:
    once = allowed_hosts_for(["localhost"], 8080)

    assert allowed_hosts_for(once, 8080) == once


# ---------------------------------------------------------------------------
# Identity settings (task 22, ADR 0015)
# ---------------------------------------------------------------------------

IDENTITY = {
    "auth_issuer": "https://idp.test/realms/acp",
    "auth_audience": "agent-control-plane",
}


def settings(**overrides: Any) -> GatewaySettings:
    return GatewaySettings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_no_identity_settings_means_unauthenticated() -> None:
    """How every task before task 22 ran. It has to keep working, or the
    gateway could not start at all until Phase 2 finishes."""
    assert settings().authentication_configured is False


def test_an_issuer_and_an_audience_turn_authentication_on() -> None:
    """There is no `ACP_AUTH_ENABLED`, and that is the point: a boolean is a
    thing somebody forgets to set, and forgetting it leaves a gateway accepting
    every request while its config claims otherwise."""
    assert settings(**IDENTITY).authentication_configured is True


def test_the_jwks_url_is_optional_because_it_can_be_discovered() -> None:
    """And better left unset. Configuring it by hand skips the RFC 8414 §3.3
    check that the key set actually belongs to the issuer being trusted — the
    mix-up achieved by copy-paste rather than by an attacker."""
    assert settings(**IDENTITY).auth_jwks_url == ""
    assert settings(**IDENTITY).authentication_configured is True


def test_an_issuers_file_turns_authentication_on() -> None:
    assert settings(auth_issuers_file="config/issuers.yaml").authentication_configured is True


@pytest.mark.parametrize("omitted", sorted(IDENTITY))
def test_issuer_without_audience_or_vice_versa_refuses_to_start(omitted: str) -> None:
    """The worst of the available states: settings that look like
    authentication and do nothing. Fatal at startup, like every other
    configuration error in this module."""
    partial = {k: v for k, v in IDENTITY.items() if k != omitted}

    with pytest.raises(ValidationError, match="all-or-nothing"):
        settings(**partial)


def test_the_error_names_what_is_missing() -> None:
    """Read by a human at 3am. "Invalid configuration" is not good enough when
    the fix is one environment variable."""
    with pytest.raises(ValidationError, match="ACP_AUTH_AUDIENCE"):
        settings(auth_issuer=IDENTITY["auth_issuer"])


def test_a_file_and_single_issuer_settings_together_are_refused() -> None:
    """Two sources disagreeing about which authorization servers are trusted is
    not a merge to be resolved."""
    with pytest.raises(ValidationError, match="mutually exclusive"):
        settings(auth_issuers_file="config/issuers.yaml", **IDENTITY)


def test_a_global_jwks_url_alongside_an_issuers_file_is_refused() -> None:
    """Per-issuer key sets belong to their issuer. One URL shared across several
    servers is the crossing this whole task exists to prevent, spelled as a
    config option."""
    with pytest.raises(ValidationError, match="per-issuer"):
        settings(auth_issuers_file="config/issuers.yaml", auth_jwks_url="https://idp.test/keys")


def test_a_jwks_url_with_no_issuer_is_refused() -> None:
    with pytest.raises(ValidationError, match="names keys for nobody"):
        settings(auth_jwks_url="https://idp.test/keys")


# ---------------------------------------------------------------------------
# The issuers file
# ---------------------------------------------------------------------------


def write_issuers(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "issuers.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_well_formed_issuers_file_loads(tmp_path: Path) -> None:
    path = write_issuers(
        tmp_path,
        """
issuers:
  - issuer: https://idp.corp.test/realms/acp
    audience: agent-control-plane
  - issuer: https://idp.partner.test/
    audience: agent-control-plane-partner
    jwks_url: https://idp.partner.test/keys
""",
    )

    documents = load_issuers(path)

    assert [d["issuer"] for d in documents] == [
        "https://idp.corp.test/realms/acp",
        "https://idp.partner.test/",
    ]
    assert "jwks_url" not in documents[0], "an absent jwks_url must stay absent, not become empty"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("issuers: []", "non-empty list", id="empty"),
        pytest.param("issuers: not-a-list", "non-empty list", id="not-a-list"),
        pytest.param("servers: []", "`issuers` key", id="wrong-key"),
        pytest.param("issuers:\n  - just-a-string", "must be a mapping", id="entry-not-a-mapping"),
        pytest.param("issuers: [oops: [", "not valid YAML", id="malformed"),
    ],
)
def test_a_malformed_issuers_file_is_a_startup_failure(
    tmp_path: Path, body: str, expected: str
) -> None:
    """Read by whoever is trying to work out why nothing can authenticate, so
    every message names the file and, where possible, the offending entry."""
    with pytest.raises(ConfigurationError, match=expected):
        load_issuers(write_issuers(tmp_path, body))


def test_a_missing_issuers_file_names_itself(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"issuers\.yaml"):
        load_issuers(tmp_path / "issuers.yaml")
