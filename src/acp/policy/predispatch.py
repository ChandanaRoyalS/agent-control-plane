"""Authorize on the routing headers, before anything parses a body.

The 2026-07-28 revision added ``Mcp-Method`` and ``Mcp-Name`` so that an
intermediary can route and authorize without reading the JSON-RPC payload. This
gateway is the exact component those headers were added for, and this is the
half that uses them.

**The one rule that makes it safe: this may refuse, and may never authorize.**

The headers are chosen by the caller, so anything decided *in the caller's
favour* on the strength of a header is decided on the attacker's say-so. So the
pre-check only ever subtracts: it refuses calls it can prove the policy would
refuse anyway, and everything it does not refuse goes on to
``enforce_call``, which reads the *body* and remains authoritative
(ADR 0027 — enforcement is the backstop).

That single direction is what makes a lying header worthless. A caller who puts
an allowed tool in the header and a forbidden one in the body gets past this
layer and is refused by the real one; a caller who does the reverse refuses
themselves. There is no combination that gains anything, which is why this
module contains no header-versus-body reconciliation: the desync it would
defend against cannot buy an attacker a call.

**And the trap that makes a naive version wrong.** A rule constraining an
argument cannot match a call whose arguments are unknown — and at header time
they are always unknown, because the body is exactly what has not been read. An
implementation that simply evaluated the policy with an empty argument mapping
would refuse every call permitted by an argument-scoped rule: a false denial of
legitimate traffic, produced by the optimisation meant to be invisible. So the
question asked here is not "would this be allowed" but the strictly weaker
**"could this ever be allowed, for any arguments at all"** — see
``could_ever_allow``.

See ADR 0043.
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
from acp.exceptions import ACPError
from acp.identity.principal import Principal, current_principal
from acp.policy.evaluate import matches_without_arguments
from acp.policy.schema import Effect, Policy
from acp.upstream.envelope import NAME_BEARING_METHODS, decode_header_value

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]

METHOD_HEADER: Final = b"mcp-method"
NAME_HEADER: Final = b"mcp-name"

TOOL_CALL_METHOD: Final = "tools/call"
"""The only method decided here — see ``_declared_tool`` for why not all three."""

MAX_HEADER_LENGTH: Final = 1024
"""Longest routing header this will look at.

A qualified tool name is bounded near 64 characters (ADR 0003). A kilobyte is
generous and finite, and the bound matters because this runs before any other
size limit in the stack.
"""

REFUSED_EVENT: Final = "policy.predispatch_refused"

PERMISSIBLE: Final = frozenset({Effect.ALLOW, Effect.REQUIRE_APPROVAL})
"""Effects under which a call may still proceed, so the fast path must not
refuse it. Named rather than inlined, because the next effect added here is the
one somebody forgets — and forgetting produces a silent false denial rather
than an error."""


def could_ever_allow(policy: Policy, principal: Principal, tool: str) -> bool:
    """Could any argument mapping make this call permitted?

    The conservative half of the evaluator, and the only question that can be
    answered honestly before a body is read. ``False`` means *no* arguments
    could rescue this call, so refusing now is refusing something the full check
    would refuse too. ``True`` means "not provably refused", which is not a
    permission — it hands the call on to the authoritative check.

    Walking the rules in document order, because first match wins (ADR 0026):

    - **An allow that matches on identity and tool** — whether or not it also
      constrains arguments — means some call could be permitted. Stop, and do
      not refuse. An allow with argument constraints is precisely the case a
      naive implementation gets wrong.
    - **So does a `require_approval` rule** (ADR 0048), and forgetting this
      would be a false refusal of exactly the kind this module exists to avoid:
      a call a human was about to approve, refused at the header before anyone
      was asked, with no rule an operator could point at to explain it.
    - **A deny with no argument constraints** matches every call to this tool by
      this principal, so it decides all of them. Stop, and refuse.
    - **A deny that constrains arguments** decides only the calls whose
      arguments match it; the others fall through to later rules. Keep walking.

    Falling off the end is the deny default (ADR 0025) — nothing matched, so
    nothing ever will, and refusing is right.

    The identity-and-tool half of the match comes from
    ``matches_without_arguments``, shared with the real evaluator, so the two
    cannot disagree about who a rule applies to. The argument half is handled by
    the branches above, because "might match" is not a question a matcher
    returning a bool can answer.
    """
    actor = principal.actor.subject if principal.actor else None
    for rule in policy.rules:
        # Arguments are deliberately excluded from this question: a rule that
        # constrains them still *applies* to this tool, and whether it fires
        # depends on a body nobody has read.
        if not matches_without_arguments(rule, principal.subject, actor, tool):
            continue
        if rule.effect in PERMISSIBLE:
            return True
        if not rule.args:
            return False
    return False


class PreDispatchAuthorizationMiddleware:
    """Refuses a request whose routing headers name a call policy cannot permit.

    Placed *inside* ``AuthenticationMiddleware`` so the principal is already
    resolved when this runs — it is added to the stack first, and Starlette's
    ``add_middleware`` inserts at the front, so first added is innermost.
    """

    def __init__(
        self, app: Any, policy: Policy | None = None, audit: AuditLog | None = None
    ) -> None:
        self._app = app
        self._policy = policy
        self._audit = audit

    def _record(self, *args: Any, **kwargs: Any) -> None:
        """Chain a refusal, swallowing a sink failure.

        A failure here does not change the outcome: the call is being refused
        either way, so fail-closed is already satisfied — nothing happens that
        is not recorded, because nothing happens. What must not happen is a 500,
        which would answer a policy refusal with a different word than the policy
        used. The writer has already logged at ERROR and moved the metric.
        """
        if self._audit is None:  # pragma: no cover — guarded by the caller
            return
        with contextlib.suppress(ACPError):
            self._audit.record(*args, **kwargs)

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or self._policy is None:
            await self._app(scope, receive, send)
            return

        tool = _declared_tool(scope)
        if tool is None:
            # No routing headers, or a method that names nothing — `tools/list`
            # carries no subject to authorize. Nothing to decide here; the
            # request proceeds to the checks that read the body.
            await self._app(scope, receive, send)
            return

        principal = current_principal()
        if principal is not None and could_ever_allow(self._policy, principal, tool):
            await self._app(scope, receive, send)
            return

        # Either there is no principal while a policy is loaded — the same
        # fail-closed misconfiguration `on_call_tool` refuses — or no arguments
        # could make this call permitted.
        logger.info(
            REFUSED_EVENT,
            extra={
                "subject": principal.subject if principal is not None else None,
                "tool": tool,
                "reason": "no principal" if principal is None else "no rule could allow",
            },
        )
        # Chained before the 403 is written. A refusal made at the header is
        # still an authorization decision, and it is the *only* record of a call
        # that never reached `enforce_call` — leaving it out would make the fast
        # path a hole in the audit trail rather than an optimisation of it.
        if self._audit is not None:
            self._audit.record(
                AuditCategory.AUTHORIZATION,
                REFUSED_EVENT,
                subject=principal.subject if principal else None,
                actor=principal.actor.subject if principal and principal.actor else None,
                tool=tool,
                outcome=AuditOutcome.DENIED,
                reason="no policy rule could permit this call, whatever its arguments",
            )
        await _refuse(send)


def _declared_tool(scope: Scope) -> str | None:
    """The *tool* named by the routing headers, or ``None`` for "do not decide".

    Every ``None`` below is a deliberate abstention rather than a refusal. This
    layer acts only on a positive proof, so anything it cannot read cleanly is
    handed to the checks that read the body — which refuse it there if it
    deserves refusing.

    **Only ``tools/call``**, though ``NAME_BEARING_METHODS`` lists three methods.
    That mapping answers "which methods carry an ``Mcp-Name`` at all", which is
    the right question for the outbound client and the wrong one here: the name
    on ``resources/read`` is a URI and the name on ``prompts/get`` is a prompt,
    and neither is a thing a policy rule is written about. Passing either to a
    tool-shaped check would find no matching rule, hit the deny default, and
    refuse a request the real check permits — the exact false refusal this whole
    design is built to avoid. The mapping is still imported, and membership
    still asserted, so that a method removed from it cannot silently keep being
    decided here.

    **The name is decoded, not compared raw.** A name outside visible ASCII —
    or one that merely looks like the codec's sentinel — travels base64-wrapped
    (``encode_header_value``), and comparing the wrapper against a policy rule
    would refuse a legitimate call for the crime of having an awkward name.
    ``decode_header_value`` is the same codec the outbound client and the mock
    server use, so all three agree on what a header says by construction, and it
    already answers ``None`` for a malformed sentinel rather than raising.
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
            # The same routing header twice, with nothing to say which one the
            # body will agree with. Declining costs a fast path; guessing risks
            # refusing the call the caller actually made.
            return None
        seen.add(lowered)
        if len(value) > MAX_HEADER_LENGTH:
            return None
        try:
            decoded = value.decode("ascii")
        except UnicodeDecodeError:
            # Not a value any conforming client sends: the codec above exists
            # precisely so that non-ASCII names travel as ASCII.
            return None
        if lowered == METHOD_HEADER:
            method = decoded
        else:
            name = decoded

    if method != TOOL_CALL_METHOD or method not in NAME_BEARING_METHODS:
        return None
    return decode_header_value(name) or None


async def _refuse(send: Any) -> None:
    """Answer 403, with a body that says nothing the caller did not already know.

    403 rather than a JSON-RPC error inside a 200, for the reason
    ``AuthenticationMiddleware`` returns 401: this happens before anything
    parses a body, and answering 200 tells every proxy in the path that the
    request succeeded.

    The message is undifferentiated on purpose — the same refusal
    ``PolicyDeniedError`` gives. Naming the rule, or distinguishing "no such
    tool" from "forbidden tool", is an oracle a caller can map one request at a
    time. The log has the detail; the caller has "no".
    """
    body = json.dumps({"error": "forbidden"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
