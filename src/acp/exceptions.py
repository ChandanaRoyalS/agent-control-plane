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
