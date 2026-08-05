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
from pydantic import Field, ValidationError
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
