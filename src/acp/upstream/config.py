"""Per-upstream configuration.

Timeouts are separate so a refused connection fails in milliseconds while a real
tool call may take thirty seconds.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Names cannot contain the `__` tool-name separator (ADR 0003): lowercase letters,
# digits and single hyphens only.
_UPSTREAM_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

MAX_UPSTREAM_NAME_LENGTH = 24
"""Leaves 38 characters for the tool half of the 64-character name (ADR 0003)."""


class UpstreamConfig(BaseModel):
    """Everything needed to talk to one upstream MCP server."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(max_length=MAX_UPSTREAM_NAME_LENGTH)
    """Short identifier qualifying tool names and labelling logs and spans."""

    url: str
    """Full URL of the upstream's MCP endpoint, e.g. ``http://mock-a:9101/mcp``."""

    audience: str = ""
    """RFC 8693 ``audience`` for token exchange, so a token fits only this upstream.

    Empty attaches no credential; once exchange is configured that is a startup
    failure.
    """

    resource: str = ""
    """This upstream's URI, sent as RFC 8707's ``resource``.

    Keycloak 26.7 ignores it (`scripts/probe_resource_indicator.py`, ADR 0020), so
    scope is enforced by checking the returned credential, not by sending this.
    """

    credential_ref: str = ""
    """Name of a stored secret to send, for an upstream that cannot do token exchange.

    A reference, never the value, so no secret lands in config. Mutually
    exclusive with `audience`.
    """

    credential_header: str = "Authorization"
    """Which header carries the static credential (e.g. `X-API-Key`)."""

    credential_scheme: str = "Bearer"
    """Prefix before the secret; empty sends the value bare."""

    connect_timeout: float = Field(default=3.0, gt=0)
    """Seconds to establish a TCP connection; short so unreachable hosts fail fast."""

    read_timeout: float = Field(default=30.0, gt=0)
    """Seconds to wait for the response body."""

    write_timeout: float = Field(default=10.0, gt=0)
    """Seconds to send the request body."""

    pool_timeout: float = Field(default=5.0, gt=0)
    """Seconds to wait for a free pooled connection."""

    max_connections: int = Field(default=20, gt=0)
    """Ceiling on concurrent sockets; kept at or above ``max_concurrency``."""

    max_keepalive_connections: int = Field(default=10, ge=0)
    """Idle connections kept warm between requests."""

    max_attempts: int = Field(default=3, ge=1)
    """Total attempts per operation, including the first. 1 disables retrying."""

    initial_backoff: float = Field(default=0.1, gt=0)
    """Seconds before the first retry, before jitter is applied."""

    max_backoff: float = Field(default=5.0, gt=0)
    """Ceiling on the backoff, in seconds."""

    idempotent_tools: tuple[str, ...] = ()
    """Tools safe to call twice, and so to retry. Empty: no tool call is retried.

    ``tools/list`` is retried regardless.
    """

    max_concurrency: int = Field(default=20, gt=0)
    """The bulkhead: in-flight calls allowed; the next is refused, not queued.

    Must not exceed ``max_connections``.
    """

    failure_threshold: int = Field(default=5, ge=1)
    """Consecutive failed attempts (not logical calls) that open the breaker."""

    reset_timeout: float = Field(default=30.0, gt=0)
    """Seconds an open circuit waits before letting a trial call through."""

    half_open_max_calls: int = Field(default=1, ge=1)
    """Concurrent trial calls allowed while the circuit is half-open."""

    cache_enabled: bool = True
    """Whether the catalogue may be cached; the upstream must still opt in."""

    max_cache_ttl_ms: int = Field(default=24 * 60 * 60 * 1000, ge=0)
    """Ceiling on the TTL the upstream advertises."""

    default_cache_ttl_ms: int = Field(default=0, ge=0)
    """Used only when a response carries no hint; zero, as in the SDK."""

    @model_validator(mode="after")
    def _one_way_to_be_credentialed(self) -> UpstreamConfig:
        """Reject setting both `audience` and `credential_ref` as ambiguous."""
        if self.audience and self.credential_ref:
            msg = (
                f"upstream {self.name!r} sets both `audience` and `credential_ref`. "
                f"The first mints a short-lived credential per call (RFC 8693); the "
                f"second sends a stored static one. Pick the first unless this "
                f"upstream cannot do it."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _bulkhead_fits_the_pool(self) -> UpstreamConfig:
        """Require the bulkhead to be narrower than the pool, so calls never queue."""
        if self.max_concurrency > self.max_connections:
            msg = (
                f"max_concurrency ({self.max_concurrency}) must not exceed "
                f"max_connections ({self.max_connections}): the bulkhead has to "
                f"refuse before the connection pool starts queueing"
            )
            raise ValueError(msg)
        return self

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not _UPSTREAM_NAME.match(value):
            msg = (
                f"upstream name {value!r} must be lowercase alphanumeric with single "
                f"hyphens (no underscores — `__` is reserved as the tool-name "
                f"separator, see ADR 0003)"
            )
            raise ValueError(msg)
        return value

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            msg = f"upstream url {value!r} must start with http:// or https://"
            raise ValueError(msg)
        return value
