"""Per-upstream configuration.

Timeouts are separate values rather than one number on purpose. "The request
took too long" hides several different failures with different correct
responses: a refused connection should fail in milliseconds, while a legitimate
tool call may reasonably take thirty seconds. Collapsing them into a single
timeout means either failing fast calls slowly or slow calls wrongly.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Upstream names must not contain the `__` separator used to qualify tool names
# (ADR 0003), or `mock-a__search` would be ambiguous. Restricting to lowercase
# letters, digits and single hyphens makes that impossible by construction
# rather than by convention.
_UPSTREAM_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

MAX_UPSTREAM_NAME_LENGTH = 24
"""Leaves 38 characters for the tool half within the 64-character budget.

Enough that truncation is rare in practice rather than routine — see ADR 0003.
"""


class UpstreamConfig(BaseModel):
    """Everything needed to talk to one upstream MCP server."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(max_length=MAX_UPSTREAM_NAME_LENGTH)
    """Short identifier. Used to qualify tool names and to label logs and spans.

    Capped so that `<upstream>__<tool>` has room for a useful tool name inside
    the 64-character budget (ADR 0003). Without the cap a long upstream name
    would force truncation on every tool, and truncated names need a catalogue
    lookup to route — turning a rare cost into a constant one.
    """

    url: str
    """Full URL of the upstream's MCP endpoint, e.g. ``http://mock-a:9101/mcp``."""

    connect_timeout: float = Field(default=3.0, gt=0)
    """Seconds to establish a TCP connection. Short: an unreachable host should
    fail fast so a circuit breaker can open, not tie up a worker."""

    read_timeout: float = Field(default=30.0, gt=0)
    """Seconds to wait for the response body. Generous: a real tool may do
    genuine work."""

    write_timeout: float = Field(default=10.0, gt=0)
    """Seconds to send the request body."""

    pool_timeout: float = Field(default=5.0, gt=0)
    """Seconds to wait for a free connection from the pool. Hitting this means
    the upstream is saturated, which is a different problem from it being slow,
    and worth being able to tell apart in metrics."""

    max_connections: int = Field(default=20, gt=0)
    """Ceiling on concurrent connections. This is the bulkhead: one saturated
    upstream must not be able to consume the whole event loop."""

    max_keepalive_connections: int = Field(default=10, ge=0)
    """Idle connections kept warm between requests."""

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
