"""The exception taxonomy, each mapped onto a JSON-RPC error the agent reasons over.

`code` values stay in JSON-RPC's implementation-defined range, -32000 to -32099.
"""

from __future__ import annotations

from typing import Any


class ACPError(Exception):
    """Base for deliberate gateway errors; any other exception at the boundary is a bug."""

    code: int = -32000
    """JSON-RPC error code returned to the caller."""

    recoverable: bool = False
    """Whether the agent could plausibly succeed by trying something different."""

    retry_locally: bool = True
    """Whether the gateway's own retry layer should retry within milliseconds.

    Separate from ``recoverable`` (advice to the agent): the gateway's own refusals,
    such as an open circuit or full bulkhead, are recoverable but last seconds, so
    retrying them locally only slows the failure.
    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}

    def to_jsonrpc_error(self) -> dict[str, Any]:
        """Render as a JSON-RPC ``error`` object; ``data`` carries ``recoverable``."""
        return {
            "code": self.code,
            "message": self.message,
            "data": {"recoverable": self.recoverable, **self.details},
        }


class ConfigurationError(ACPError):
    """Invalid configuration at startup; fatal so the gateway never starts open."""

    code = -32001
    recoverable = False


class AuthenticationError(ACPError):
    """The caller did not prove who they are.

    Recoverable after re-authenticating, not by retrying the same token. The
    ``reason`` in ``details`` is for the log and is stripped before reaching the
    caller (``acp.identity.asgi``) so it cannot serve as an oracle.
    """

    code = -32030
    recoverable = True


class IdentityProviderUnavailableError(ACPError):
    """The authorization server could not be reached, or answered nonsense.

    Not an ``AuthenticationError``: "cannot check your token" must say retry, not
    re-authenticate, or an identity-provider outage becomes a login storm.
    """

    code = -32031
    recoverable = True


# ---------------------------------------------------------------------------
# Upstream failures. `recoverable` reaches the agent and decides whether it retries;
# a wrong value means a stuck agent or a retry loop.
# ---------------------------------------------------------------------------


class CredentialExchangeError(ACPError):
    """The gateway could not obtain a credential for an upstream.

    The call is refused rather than sent without a credential or with the caller's
    token. A refused exchange (unknown audience, client not permitted, wrong ``aud``)
    is not recoverable; an unreachable server raises the subclass below.
    """

    code = -32032

    retry_locally = False
    """Not retried in the upstream's budget, so an identity outage is not charged to it."""


class CredentialProviderUnavailableError(CredentialExchangeError):
    """The authorization server could not be reached, or answered 5xx.

    A subclass, unlike ``IdentityProviderUnavailableError``: no shared handler here
    turns it into a 401; only the ``recoverable`` advice differs.
    """

    code = -32033

    recoverable = True


class UpstreamError(ACPError):
    """Base for anything that went wrong talking to an upstream MCP server."""

    code = -32010

    def __init__(
        self, message: str, *, upstream: str, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, details={"upstream": upstream, **(details or {})})
        self.upstream = upstream


class UpstreamTimeoutError(UpstreamError):
    """The upstream did not answer within its configured budget; may succeed on retry."""

    code = -32011
    recoverable = True


class UpstreamUnavailableError(UpstreamError):
    """The upstream could not be reached (connection refused, DNS, TLS); recoverable."""

    code = -32012
    recoverable = True


class UpstreamProtocolError(UpstreamError):
    """The upstream answered with invalid JSON-RPC; not recoverable, retries repeat it."""

    code = -32013
    recoverable = False


class UnknownUpstreamError(UpstreamError):
    """A qualified tool name referenced an unconfigured upstream; usually a stale catalogue."""

    code = -32015
    recoverable = False


class UnknownToolError(UpstreamError):
    """A possibly truncated name matched no tool even after re-reading the catalogue."""

    code = -32016
    recoverable = False


class UpstreamCircuitOpenError(UpstreamError):
    """The circuit breaker is open, so the call was never made.

    ``retry_after_seconds`` is the time until the breaker allows a trial call.
    Not retried locally: the reset timeout is seconds, the backoff milliseconds.
    """

    code = -32017
    recoverable = True
    retry_locally = False

    def __init__(
        self,
        message: str,
        *,
        upstream: str,
        retry_after_seconds: float,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            upstream=upstream,
            details={"retry_after_seconds": round(retry_after_seconds, 3), **(details or {})},
        )
        self.retry_after_seconds = retry_after_seconds


class UpstreamOverloadedError(UpstreamError):
    """The bulkhead is full: the upstream has its maximum in-flight calls; not sent.

    Says nothing about upstream health. Not retried locally, which would add load
    to a saturated upstream.
    """

    code = -32018
    recoverable = True
    retry_locally = False


class UpstreamRejectedError(UpstreamError):
    """The upstream returned a well-formed JSON-RPC error, kept as ``upstream_code``.

    A protocol rejection only; a tool that ran and failed is an ``isError`` result.
    """

    code = -32014
    recoverable = False

    def __init__(
        self,
        message: str,
        *,
        upstream: str,
        upstream_code: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message, upstream=upstream, details={"upstream_code": upstream_code, **(details or {})}
        )
        self.upstream_code = upstream_code


class PolicyDeniedError(ACPError):
    """A policy rule refused this call, or no rule allowed it; not recoverable.

    ``details`` carries the deciding rule (``None`` for the default deny) for the
    audit log only; telling the caller which rule denied it would be an oracle.
    """

    code = -32040
    recoverable = False


class ApprovalUnsupportedError(ACPError):
    """The call needs approval but this client cannot receive `input_required`.

    Holding uses `input_required` (ADR 0048), which pre-2026-07-28 clients cannot
    resume (ADR 0072). Raised before an approval is created; not recoverable.
    """

    code = -32041
    recoverable = False


class RateLimitExceededError(ACPError):
    """The caller's per-principal token bucket is empty; wait, then retry.

    ``details`` carries ``retry_after`` seconds, a hint that reveals only the
    caller's own limit.
    """

    code = -32050
    recoverable = True


class QuotaExceededError(ACPError):
    """The caller has used up their allowance for the current window; recoverable.

    ``details`` carries ``retry_after``, the seconds until the caller's own window
    resets.
    """

    code = -32051
    recoverable = True


class AuditUnavailableError(ACPError):
    """This call could not be audited, so it was not made.

    Disabled by ``ACP_AUDIT_REQUIRED=false``. Recoverable. The wire message names
    nothing, so callers cannot learn which subsystem to attack; the reason goes to
    the ERROR log and a metric.
    """

    code = -32060
    recoverable = True


class StateStoreUnavailableError(ACPError):
    """The approval or budget store could not be reached in time.

    The call fails closed with a recoverable code (ADR 0070); the wire message
    names no store, as with `AuditUnavailableError`.
    """

    code = -32070
    recoverable = True
