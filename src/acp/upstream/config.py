"""Per-upstream configuration.

Timeouts are separate values rather than one number on purpose. "The request
took too long" hides several different failures with different correct
responses: a refused connection should fail in milliseconds, while a legitimate
tool call may reasonably take thirty seconds. Collapsing them into a single
timeout means either failing fast calls slowly or slow calls wrongly.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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

    audience: str = ""
    """What a credential for this upstream must be minted for (task 27).

    The value the gateway sends as RFC 8693's ``audience`` when exchanging the
    caller's token, and the ``aud`` the resulting credential carries. It names
    *this upstream* to the authorization server, which is what makes a token for
    one upstream useless against another — the confused-deputy defence, spelled
    as configuration.

    Empty means no credential is attached. That is the correct default while
    exchange is unconfigured, and a **startup failure** once it is: an upstream
    silently reached without a credential, in a deployment that believes every
    call is scoped, is the failure mode this whole phase exists to remove.
    """

    resource: str = ""
    """This upstream's identity as a URI, sent as RFC 8707's ``resource``.

    The specified way to name an exchange target, and — measured against
    Keycloak 26.7 — a parameter it accepts and silently discards
    (`scripts/probe_resource_indicator.py`, ADR 0020). It is sent anyway,
    because a gateway that only works against one authorization server is not a
    gateway, and any conformant server narrows on it.

    What must never happen is treating *sending* it as the control. The scope is
    enforced by checking the credential that comes back, not by trusting that
    the request was honoured.
    """

    credential_ref: str = ""
    """Name of a secret in the store to send to this upstream (task 29).

    The other door, for an upstream that cannot take part in token exchange —
    an API key issued out of band, a vendor appliance that will never speak
    RFC 8693. Before task 29 such an upstream could not be configured at all,
    because task 27 made `audience` mandatory once exchange was on.

    A *reference*, never a value. A credential in this file is a credential in
    git, in every backup of the config directory, and in the diff of whoever
    added it. What lives here is a name; the value lives in the store.

    Mutually exclusive with `audience`: an upstream is credentialed one way or
    the other, and a config declaring both is one where nobody can say which
    credential the upstream actually receives.
    """

    credential_header: str = "Authorization"
    """Which header carries the static credential.

    `Authorization` is right for anything OAuth-shaped and wrong for a great
    many real APIs, which want `X-API-Key` or worse. Configurable because the
    alternative is a gateway that can only broker for servers that agreed on a
    convention — and the whole premise is standing in front of systems that did
    not agree on anything.
    """

    credential_scheme: str = "Bearer"
    """Prefix before the secret. Empty sends the value bare, which is what an
    `X-API-Key` header wants and what `Authorization` never does."""

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
    """Ceiling on concurrent *sockets* to this upstream.

    Not the bulkhead — that is ``max_concurrency``, which bounds calls and
    refuses rather than waits. This is the pool behind it, and configuration
    keeps it at or above the bulkhead so it can never be the thing that
    saturates first.
    """

    max_keepalive_connections: int = Field(default=10, ge=0)
    """Idle connections kept warm between requests."""

    max_attempts: int = Field(default=3, ge=1)
    """Total attempts per operation, including the first. 1 disables retrying."""

    initial_backoff: float = Field(default=0.1, gt=0)
    """Seconds before the first retry, before jitter is applied."""

    max_backoff: float = Field(default=5.0, gt=0)
    """Ceiling on the backoff, so exponential growth cannot exceed a deadline."""

    idempotent_tools: tuple[str, ...] = ()
    """Tools that are safe to call more than once, and so safe to retry.

    Empty by default, which means **no tool call is ever retried** unless
    someone explicitly said it was safe. That default is the conservative
    direction on purpose: a timeout means *no answer*, not *no effect*, so a
    retried ``create_ticket`` may well file a second ticket while the client
    believes the first one failed. Read-only tools — search, get, list — are
    the ones that belong here.

    ``tools/list`` is retried regardless; it is a read by definition.
    """

    max_concurrency: int = Field(default=20, gt=0)
    """The bulkhead: concurrent in-flight calls allowed to this upstream.

    Call number ``max_concurrency + 1`` is refused immediately rather than
    queued, so one slow upstream cannot occupy the whole gateway while the
    healthy ones go unanswered. Must not exceed ``max_connections``; see
    :meth:`_bulkhead_fits_the_pool`.
    """

    failure_threshold: int = Field(default=5, ge=1)
    """Consecutive failures that open this upstream's circuit breaker.

    Counted per attempt, not per logical call — a call that fails three retries
    contributes three. Set to a very large number to effectively disable the
    breaker for an upstream that must never be withdrawn.
    """

    reset_timeout: float = Field(default=30.0, gt=0)
    """Seconds an open circuit waits before letting a trial call through."""

    half_open_max_calls: int = Field(default=1, ge=1)
    """Concurrent trial calls allowed while the circuit is half-open.

    One by default: a service that has just come back up is the last thing that
    should receive a burst.
    """

    cache_enabled: bool = True
    """Whether this upstream's catalogue may be cached at all.

    Even when true, nothing is cached unless the upstream itself asks for it —
    a response with no ``ttlMs``, or one marked ``private``, is never held.
    """

    max_cache_ttl_ms: int = Field(default=24 * 60 * 60 * 1000, ge=0)
    """Ceiling on whatever the upstream advertises.

    A hint is input from a system the gateway does not control. An upstream
    asking for a day — by bug or by design — would otherwise freeze its
    catalogue for a day, and the gateway would keep offering tools that no
    longer exist.
    """

    default_cache_ttl_ms: int = Field(default=0, ge=0)
    """Used only when a response carries no hint at all.

    Zero, matching the SDK: an upstream that says nothing has not agreed to
    anything, and inferring consent from silence is how a gateway serves a
    catalogue its owner never sanctioned.
    """

    @model_validator(mode="after")
    def _one_way_to_be_credentialed(self) -> UpstreamConfig:
        """`audience` and `credential_ref` are alternatives, not a pair.

        Both set is not a richer configuration, it is an ambiguous one: two
        mechanisms that each want to own the `Authorization` header, resolved by
        whichever branch happens to run first. That is a coin toss decided in
        code rather than by the person deploying it, and the failure it produces
        — an upstream reached with the wrong credential — looks like an
        authorization bug three systems away.
        """
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
        """The bulkhead must be the narrower of the two limits.

        If it were wider, the connection pool would saturate first and calls
        would queue for ``pool_timeout`` — silently reintroducing exactly the
        unbounded waiting the bulkhead exists to prevent, and reporting it as a
        timeout rather than as overload. Enforcing the ordering here means a
        pool timeout in production is unambiguously a bug rather than routine
        backpressure.
        """
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
