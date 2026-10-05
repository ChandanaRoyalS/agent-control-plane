"""Authorize on the routing headers, before anything parses a body.

Uses the ``Mcp-Method`` and ``Mcp-Name`` headers (2026-07-28 revision). Headers are
caller-chosen, so this may refuse but never authorize: it refuses only calls
``could_ever_allow`` proves no arguments could permit, and everything else goes to
``enforce_call``, which reads the body and stays authoritative (ADR 0027). A lying
header therefore gains nothing, so no header-body reconciliation is needed (ADR 0043).
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import MutableMapping, Sequence
from typing import Any, Final

from acp.audit import AuditLog
from acp.audit import Category as AuditCategory
from acp.audit import Outcome as AuditOutcome
from acp.exceptions import ACPError, PolicyDeniedError
from acp.identity.principal import current_principal
from acp.policy.evaluate import could_ever_allow
from acp.policy.schema import Policy
from acp.policy.tenancy import PolicySet
from acp.upstream.envelope import NAME_BEARING_METHODS, decode_header_value

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]

METHOD_HEADER: Final = b"mcp-method"
NAME_HEADER: Final = b"mcp-name"

TOOL_CALL_METHOD: Final = "tools/call"
"""The only method decided here — see ``_declared_tool`` for why not all three."""

MAX_HEADER_LENGTH: Final = 1024
"""Longest routing header read; this runs before any other size limit (ADR 0003)."""

REFUSED_EVENT: Final = "policy.predispatch_refused"


class PreDispatchAuthorizationMiddleware:
    """Refuses a request whose routing headers name a call policy cannot permit.

    Must sit inside ``AuthenticationMiddleware`` so the principal is resolved: add it
    first, since Starlette's ``add_middleware`` makes the first added innermost.
    """

    def __init__(
        self,
        app: Any,
        policy: Policy | PolicySet | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._app = app
        # Same normalisation as `build_server`; this is constructed independently.
        self._policies = (
            policy if isinstance(policy, PolicySet) or policy is None else PolicySet(policy)
        )
        self._audit = audit

    async def _record(self, *args: Any, **kwargs: Any) -> None:
        """Chain a refusal, swallowing a sink failure.

        The call is refused either way, so fail-closed holds; a 500 would misreport the
        refusal. The writer has already logged at ERROR and moved the metric.
        """
        if self._audit is None:  # pragma: no cover — guarded by the caller
            return
        with contextlib.suppress(ACPError):
            # On a thread, so the cheap refusal path never blocks the event loop.
            await self._audit.arecord(*args, **kwargs)

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or self._policies is None:
            await self._app(scope, receive, send)
            return

        tool = _declared_tool(scope)
        if tool is None:
            # Nothing to decide; the body checks still run.
            await self._app(scope, receive, send)
            return

        principal = current_principal()
        if principal is not None and could_ever_allow(
            self._policies.policy_for(principal.tenant), principal, tool
        ):
            await self._app(scope, receive, send)
            return

        # No principal with a policy loaded (fail closed, as `on_call_tool` does),
        # or no arguments could permit this call.
        logger.info(
            REFUSED_EVENT,
            extra={
                "subject": principal.subject if principal is not None else None,
                "tool": tool,
                "reason": "no principal" if principal is None else "no rule could allow",
            },
        )
        # Chained before the 403: the only audit record of a call that never
        # reaches `enforce_call`.
        if self._audit is not None:
            await self._record(
                AuditCategory.AUTHORIZATION,
                REFUSED_EVENT,
                subject=principal.subject if principal else None,
                actor=principal.actor.subject if principal and principal.actor else None,
                tenant=principal.tenant if principal else None,
                tool=tool,
                outcome=AuditOutcome.DENIED,
                reason="no policy rule could permit this call, whatever its arguments",
            )
        await _refuse(send)


def _declared_tool(scope: Scope) -> str | None:
    """Return the tool named by the routing headers, or ``None`` to abstain.

    ``None`` hands the request to the body checks; anything unclear abstains. Only
    ``tools/call`` is decided: the names on ``resources/read`` and ``prompts/get`` are
    not tools, and checking them would falsely refuse. Membership in
    ``NAME_BEARING_METHODS`` is still asserted. The name is decoded with the shared
    ``decode_header_value`` codec, since awkward names travel base64-wrapped.
    """
    headers: Sequence[tuple[bytes, bytes]] = scope.get("headers") or []
    method: str | None = None
    name: str | None = None
    seen: set[bytes] = set()
    for key, value in headers:
        lowered = key.lower()
        if lowered not in (METHOD_HEADER, NAME_HEADER):
            continue
        if lowered in seen:
            # A duplicate header is ambiguous; abstain rather than guess.
            return None
        seen.add(lowered)
        if len(value) > MAX_HEADER_LENGTH:
            return None
        try:
            decoded = value.decode("ascii")
        except UnicodeDecodeError:
            # Conforming clients encode non-ASCII names as ASCII.
            return None
        if lowered == METHOD_HEADER:
            method = decoded
        else:
            name = decoded

    if method != TOOL_CALL_METHOD or method not in NAME_BEARING_METHODS:
        return None
    return decode_header_value(name) or None


REFUSAL: Final = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": PolicyDeniedError.code,
            "message": "this call was not permitted",
            "data": {"recoverable": PolicyDeniedError.recoverable},
        },
    }
).encode()
"""The JSON-RPC error the handler would send, with ``id`` null since the body is unread.

Clients still match it to the pending call via the streamable-HTTP transport (ADR 0072).
"""


async def _refuse(send: Any) -> None:
    """Answer 403 carrying the same JSON-RPC error `enforce_call` would give.

    A 403, not a 200, so proxies do not see success; a JSON-RPC body so MCP clients read
    it as a non-recoverable denial (ADR 0072). The message is undifferentiated, so
    callers cannot map the policy.
    """
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(REFUSAL)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": REFUSAL})
