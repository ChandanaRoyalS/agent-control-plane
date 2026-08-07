"""The exception taxonomy.

Every error that crosses the gateway boundary is deliberately mapped onto a
JSON-RPC error response. This matters more than usual here because *the caller
is a language model*: an error is not just a log line for a human, it is context
the agent will reason over and act on. An error that explains what to do instead
produces better agent behaviour than an opaque failure.

Subclasses are added as the layers land (upstream, policy, identity, budget,
firewall). Keep `code` values aligned with the JSON-RPC spec: -32000 to -32099
is the implementation-defined server error range.
"""

from __future__ import annotations

from typing import Any


class ACPError(Exception):
    """Base class for every error the gateway raises deliberately.

    Anything that is *not* an ``ACPError`` reaching the boundary is a bug, and
    should be logged as such rather than returned to the caller.
    """

    code: int = -32000
    """JSON-RPC error code returned to the caller."""

    recoverable: bool = False
    """Whether the agent could plausibly succeed by trying something different."""

    retry_locally: bool = True
    """Whether the gateway's *own* retry layer should try again immediately.

    Deliberately separate from ``recoverable``, because the two answer different
    questions on different timescales. ``recoverable`` is advice to the agent:
    "this is worth another go, later, or with a different tool." This flag is a
    decision about the current request: "another attempt, within the next few
    hundred milliseconds, could plausibly change the outcome."

    They usually agree. Where they part company is a failure the gateway raised
    *itself* — an open circuit, a full bulkhead. Both are genuinely recoverable
    from the agent's point of view, and both are pointless to retry in-process:
    the condition is measured in seconds, the backoff in milliseconds, so every
    attempt is spent waiting on something no local retry can influence. Retrying
    them converts a fast, honest failure into a slow one, which is the exact
    behaviour the circuit breaker exists to eliminate.
    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}

    def to_jsonrpc_error(self) -> dict[str, Any]:
        """Render as a JSON-RPC ``error`` object.

        The ``data`` payload is what the agent actually sees, so it carries the
        recoverability hint rather than hiding it in a log.
        """
        return {
            "code": self.code,
            "message": self.message,
            "data": {"recoverable": self.recoverable, **self.details},
        }


class ConfigurationError(ACPError):
    """Raised at startup when configuration is invalid.

    Deliberately fatal: a gateway with a malformed policy or a missing upstream
    credential must refuse to start rather than fail open on the first request.
    """

    code = -32001
    recoverable = False


class AuthenticationError(ACPError):
    """The caller did not prove who they are.

    ``recoverable`` is **true**, and that is a statement about the agent rather
    than about the request: a token that has expired can be exchanged for a new
    one and the call retried, which is a genuinely different instruction from
    "this will never work". It is not, however, a suggestion to retry the same
    token — the agent is expected to re-authenticate first.

    Carries a ``reason`` in ``details`` for the log. That reason is stripped
    before anything is written to the caller (see ``acp.identity.asgi``): a
    validator that distinguishes "expired" from "wrong audience" from "bad
    signature" is an oracle an attacker can query one request at a time.
    """

    code = -32030
    recoverable = True


class IdentityProviderUnavailableError(ACPError):
    """The authorization server could not be reached, or answered nonsense.

    Deliberately **not** a subclass of ``AuthenticationError``, and the
    distinction is the whole reason it exists. "Your token is bad" and "I cannot
    currently check your token" are different statements with different correct
    responses: the first says get a new token, the second says try again. Report
    the second as the first and every agent in the fleet goes off to
    re-authenticate against an identity provider that is already down — a
    dependency outage converted into a login storm.

    Discovered by a test asserting the status code rather than by design: the
    key cache originally raised ``AuthenticationError`` for both.
    """

    code = -32031
    recoverable = True


# ---------------------------------------------------------------------------
# Upstream failures
#
# The `recoverable` flag on each of these is not decoration. It is forwarded to
# the agent in the JSON-RPC `data` payload, and it is the signal the agent uses
# to decide whether to try again, try a different tool, or give up. Setting it
# wrongly produces either a stuck agent or an infinite retry loop.
# ---------------------------------------------------------------------------


class UpstreamError(ACPError):
    """Base for anything that went wrong talking to an upstream MCP server."""

    code = -32010

    def __init__(
        self, message: str, *, upstream: str, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, details={"upstream": upstream, **(details or {})})
        self.upstream = upstream


class UpstreamTimeoutError(UpstreamError):
    """The upstream did not answer within its configured budget.

    Recoverable: a timeout says nothing about whether the request was valid, and
    the same call may well succeed on a retry.
    """

    code = -32011
    recoverable = True


class UpstreamUnavailableError(UpstreamError):
    """The upstream could not be reached at all — connection refused, DNS, TLS.

    Recoverable in the sense that matters to an agent: the tool is not broken,
    it is temporarily unreachable, so routing around it is the right response.
    """

    code = -32012
    recoverable = True


class UpstreamProtocolError(UpstreamError):
    """The upstream answered, but not with valid JSON-RPC.

    Deliberately *not* recoverable. A malformed response means the upstream is
    broken or is not an MCP server at all, and retrying will produce the same
    garbage while burning the agent's budget.
    """

    code = -32013
    recoverable = False


class UnknownUpstreamError(UpstreamError):
    """A qualified tool name referenced an upstream that is not configured.

    Not recoverable: the agent cannot conjure the upstream into existence, and
    the tool catalogue it was given never contained this name. Almost always
    means a stale catalogue or a hand-written tool name.
    """

    code = -32015
    recoverable = False


class UnknownToolError(UpstreamError):
    """A qualified name could not be resolved to a tool on its upstream.

    Reached only for names that may have been truncated, after re-reading the
    upstream's catalogue. Usually means the upstream removed the tool between
    the agent listing it and calling it.
    """

    code = -32016
    recoverable = False


class UpstreamCircuitOpenError(UpstreamError):
    """The gateway refused to call this upstream, because it is failing.

    Not a report of a failed call — the call never happened. The breaker has
    already watched enough consecutive failures to conclude the upstream is
    unhealthy, and is now failing fast rather than making every caller wait out
    a full timeout to rediscover the same thing.

    Recoverable, and it says so with a concrete number: ``retry_after_seconds``
    is how long until the breaker will next allow a trial call. An agent given
    that can plan around the outage instead of hammering it.

    ``retry_locally`` is False. The reset timeout is seconds; the retry backoff
    is milliseconds. Retrying here would burn the request's whole attempt budget
    against a gate that has not had time to move.
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
    """This upstream already has as many in-flight calls as it is allowed.

    The bulkhead's refusal. Like an open circuit, the request was never sent, so
    nothing happened upstream — but unlike an open circuit this says nothing
    about the upstream's health. It says the gateway is protecting itself: one
    slow upstream must not be able to hold every worker in the process hostage
    while the other upstreams sit idle and answerable.

    ``retry_locally`` is False for a second reason as well as the timing one:
    retrying into a saturated upstream is adding load to the thing that is
    already overloaded.
    """

    code = -32018
    recoverable = True
    retry_locally = False


class UpstreamRejectedError(UpstreamError):
    """The upstream returned a well-formed JSON-RPC error.

    This is the upstream working correctly and saying no — unknown method,
    unknown tool, bad parameters. It carries the upstream's own error code so
    the gateway can map it rather than flattening every rejection into one.

    Note this is a *protocol* rejection. A tool that ran and failed is not an
    error at all at this layer: MCP reports that as ``isError`` inside a normal
    result, and it is returned to the caller as data.
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
