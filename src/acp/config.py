"""Configuration, loaded once at startup and never mutated.

Three sources, in decreasing precedence: environment variables prefixed
``ACP_``, a ``.env`` file for local development, and defaults declared here.
Upstreams come from a separate YAML file because a list of servers with
per-server timeouts does not fit comfortably in flat environment variables.

**Everything here fails fast.** A malformed config, an unreadable upstreams
file, two upstreams sharing a name — all of it raises ``ConfigurationError``
before the server binds a port. That is deliberate: a gateway that starts with
a broken policy or a missing credential and discovers it on the first request
has already failed open, which for a security control is the worst possible
outcome. Refusing to start is the safe direction.

**No secrets in the YAML.** Secret-shaped values are read from a directory of
files, the convention container runtimes actually use — Docker and Kubernetes
both mount secrets as files rather than environment variables, because the
environment of a process is readable by anything that can see ``/proc``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from acp.exceptions import ConfigurationError
from acp.upstream import UpstreamConfig

DEFAULT_SECRETS_DIR = "/run/secrets"
"""Where container runtimes mount secrets.

Docker and Kubernetes both mount secrets as files rather than environment
variables, because a process's environment is readable by anything that can see
``/proc``.
"""


def _secrets_dir() -> str | None:
    """The secrets directory, or None when it does not exist.

    Returning None rather than a missing path is deliberate: pydantic-settings
    emits a ``UserWarning`` for a non-existent secrets directory, and this
    project runs tests with warnings escalated to errors. A development machine
    legitimately has no ``/run/secrets``, so warning about it is noise — but
    silencing the warning globally would also hide a *misconfigured* secrets
    path in production, which is exactly the case worth hearing about.
    """
    path = Path(os.environ.get("ACP_SECRETS_DIR", DEFAULT_SECRETS_DIR))
    return str(path) if path.is_dir() else None


class GatewaySettings(BaseSettings):
    """Process-level settings for the gateway."""

    model_config = SettingsConfigDict(
        env_prefix="ACP_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=_secrets_dir(),
        extra="forbid",
        frozen=True,
    )

    host: str = "127.0.0.1"
    """Interface to bind. Defaults to loopback: a gateway that binds every
    interface by accident is exposed before anyone decides it should be."""

    port: int = Field(default=8080, gt=0, le=65535)

    log_level: str = "INFO"

    log_format: str = "auto"
    """``json``, ``console``, or ``auto`` to pick by whether stderr is a
    terminal. Production gets JSON without anyone having to remember to ask for
    it, and a developer at a terminal gets something readable."""

    admin_host: str = "127.0.0.1"
    """Interface for the metrics and health listener.

    Loopback by default, and deliberately a *separate* listener from the
    gateway. A scrape endpoint publishes every upstream name, every tool name
    and which dependencies are currently failing — a reconnaissance report for
    anyone choosing what to attack. Exposing it beyond the host should be a
    deliberate act, not the default.
    """

    admin_port: int = Field(default=9090, gt=0, le=65535)

    admin_enabled: bool = True

    health_probing_enabled: bool = True
    """Background probing of upstream health.

    Off means the gateway behaves exactly as it did before task 18: every
    upstream is attempted on every request, and a breaker recovers only when
    some agent's request happens to become its trial call.
    """

    health_probe_interval: float = Field(default=15.0, gt=0)
    """Seconds between probe rounds, before jitter."""

    schema_drift_detection_enabled: bool = True
    """Compare each probed catalogue against the committed baseline (task 20).

    Detection rides on the health prober, so this does nothing when
    ``health_probing_enabled`` is off — see ``acp.schema.detector`` for why that
    is the right place for it rather than the request path.
    """

    schema_baseline_file: Path = Path("config/schema-baseline.json")
    """The acknowledged state of every upstream's catalogue.

    A missing file is not an error: it means nothing has been baselined yet, and
    the gateway says so once per upstream rather than refusing to start. A file
    that exists and cannot be parsed is logged loudly and treated as absent —
    deliberately unlike every other configuration failure in this module, which
    are fatal. A drift detector is a monitor, and a monitor that can stop the
    gateway from starting is a larger risk than the one it was added to reduce.
    """

    upstreams_file: Path = Path("config/upstreams.yaml")
    """Path to the upstream definitions, resolved relative to the process's
    working directory."""

    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    """Hosts the inbound server will accept, for DNS-rebinding protection.

    Deployment behind a real hostname must set this — the defaults only cover
    local development, and the SDK rejects any ``Host`` not listed. Discovered
    the hard way in task 9: the SDK's own allow-list has no default at all, so
    an unconfigured server rejects every request including from localhost.
    """

    allowed_origins: list[str] = Field(default_factory=list)
    """Browser origins accepted. Empty is correct for non-browser clients."""

    # -- identity (Phase 2) ------------------------------------------------
    #
    # There is deliberately no `ACP_AUTH_ENABLED`. Authentication is on when an
    # identity provider is configured and off when one is not, because a boolean
    # is a thing somebody forgets to set — and the failure mode of forgetting is
    # a gateway that accepts every request while its configuration says it
    # authenticates them. Presence of configuration cannot be forgotten in that
    # direction: you cannot validate tokens without an issuer.
    #
    # Setting *some* of these and not the others is a startup failure. Half
    # configured authentication that silently does nothing is the worst of the
    # three possible states.

    auth_issuer: str = ""
    """The authorization server's issuer URL. Must match the token's ``iss``."""

    auth_audience: str = ""
    """This gateway's identifier, checked against the token's ``aud``.

    Not optional when authentication is on. A token minted for another service
    in the estate is correctly signed and unexpired, and accepting it would let
    anything that can obtain *any* token act through this gateway.
    """

    auth_jwks_url: str = ""
    """Where the authorization server publishes its signing keys."""

    auth_algorithms: list[str] = Field(
        default_factory=lambda: ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]
    )
    """Signature algorithms accepted. Asymmetric only — a symmetric algorithm
    here is refused at startup, because a JWKS publishes *public* keys and an
    attacker can sign HS256 with one."""

    auth_leeway: float = Field(default=60.0, ge=0)
    """Clock skew tolerated on ``exp``, ``nbf`` and ``iat``, in seconds."""

    auth_jwks_cache_ttl: float = Field(default=600.0, gt=0)

    auth_jwks_min_refresh_interval: float = Field(default=30.0, ge=0)
    """Floor between key-set fetches triggered by an unknown ``kid``.

    A rate limit on attacker-triggered work: the ``kid`` comes from the token,
    so refetching on every miss makes the gateway an amplifier pointed at its
    own identity provider.
    """

    @property
    def authentication_configured(self) -> bool:
        return bool(self.auth_issuer and self.auth_audience and self.auth_jwks_url)

    @model_validator(mode="after")
    def _identity_settings_are_all_or_nothing(self) -> GatewaySettings:
        provided = {
            "ACP_AUTH_ISSUER": self.auth_issuer,
            "ACP_AUTH_AUDIENCE": self.auth_audience,
            "ACP_AUTH_JWKS_URL": self.auth_jwks_url,
        }
        missing = [name for name, value in provided.items() if not value]
        if missing and len(missing) != len(provided):
            msg = (
                "identity settings are all-or-nothing; "
                f"missing {', '.join(sorted(missing))}. "
                "Set all three to authenticate, or none to run unauthenticated."
            )
            raise ValueError(msg)
        return self


def allowed_hosts_for(hosts: list[str], port: int) -> list[str]:
    """Expand an allow-list to cover the port-qualified form of each host.

    The HTTP ``Host`` header carries the port for any non-default port, so a
    client reaching ``http://127.0.0.1:8080/mcp`` sends ``Host: 127.0.0.1:8080``
    — which does not match a bare ``127.0.0.1`` in the allow-list, and the SDK
    answers 421 Misdirected Request.

    This was missed by the entire test suite because those tests connect on the
    default port, where the Host header has no port suffix at all. It surfaced
    the first time a real MCP client connected on :8080. Entries that already
    specify a port are left alone, so an explicit ``gateway.internal:443`` is
    not mangled.
    """
    expanded: list[str] = []

    def add(value: str) -> None:
        # Order-preserving dedup, so applying this twice is a no-op. Duplicates
        # in an allow-list are harmless but make a config dump confusing to read.
        if value not in expanded:
            expanded.append(value)

    for host in hosts:
        add(host)
        if ":" not in host:
            add(f"{host}:{port}")
    return expanded


def load_upstreams(path: Path) -> list[UpstreamConfig]:
    """Read and validate the upstream definitions.

    Every failure mode here is a startup failure with a message naming the file
    and, where possible, the offending entry. Configuration errors are read by
    a human at 3am; "validation error for UpstreamConfig" without a filename is
    not good enough.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read upstreams file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"upstreams file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc

    if document is None:
        msg = f"upstreams file {str(path)!r} is empty"
        raise ConfigurationError(msg)
    if not isinstance(document, dict) or "upstreams" not in document:
        msg = f"upstreams file {str(path)!r} must be a mapping with an `upstreams` key"
        raise ConfigurationError(msg)

    entries = document["upstreams"]
    if not isinstance(entries, list):
        msg = f"`upstreams` in {str(path)!r} must be a list"
        raise ConfigurationError(msg)

    configs: list[UpstreamConfig] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            msg = (
                f"upstream #{index} in {str(path)!r} must be a mapping, got {type(entry).__name__}"
            )
            raise ConfigurationError(msg)
        try:
            configs.append(UpstreamConfig.model_validate(entry))
        except ValidationError as exc:
            label = entry.get("name", f"#{index}")
            msg = f"upstream {label!r} in {str(path)!r} is invalid: {exc}"
            raise ConfigurationError(msg) from exc

    _reject_duplicate_names(configs, path)
    return configs


def _reject_duplicate_names(configs: list[UpstreamConfig], path: Path) -> None:
    """Two upstreams sharing a name would make qualified tool names ambiguous.

    ``mock-a__search`` must identify exactly one server, or routing silently
    sends calls to whichever happened to be registered last (ADR 0003).
    """
    seen: set[str] = set()
    for config in configs:
        if config.name in seen:
            msg = (
                f"upstream name {config.name!r} appears more than once in {str(path)!r}; "
                f"names must be unique because tool qualification depends on them"
            )
            raise ConfigurationError(msg)
        seen.add(config.name)


def load_settings(**overrides: Any) -> GatewaySettings:
    """Build settings from the environment, failing loudly on bad values."""
    try:
        return GatewaySettings(**overrides)
    except ValidationError as exc:
        msg = f"invalid gateway configuration: {exc}"
        raise ConfigurationError(msg) from exc
