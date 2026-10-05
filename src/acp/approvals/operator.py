"""The operator channel where a human answers a held call (ADR 0049).

The agent cannot approve its own call: it speaks to the MCP listener on `:8080`,
while operators decide on the admin listener on `:9090` (loopback by default)
behind a credential the request path never sees (ADR 0049 §4); likewise
`_await_approval` ignores `input_responses`. Operators authenticate with a JWT for
`ACP_APPROVAL_OPERATOR_AUDIENCE` (verified, tenant-scoped) or the weaker shared
`ACP_APPROVAL_OPERATOR_TOKEN`, audited as `shared-token`. Routes exist only when
an operator credential is configured. Arguments are agent-chosen, so they leave as
JSON data with `UNTRUSTED_NOTICE` (as ADR 0038 fences content for agents).
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from acp.approvals.record import ApprovalRequest, State
from acp.approvals.store import ApprovalStore
from acp.audit import AuditLog
from acp.audit import Category as AuditCategory
from acp.audit import Outcome as AuditOutcome
from acp.exceptions import ACPError
from acp.identity import TokenValidator

APPROVALS_PATH: Final = "/approvals"
APPROVAL_PATH: Final = "/approvals/{token}"

MIN_OPERATOR_TOKEN_LENGTH: Final = 16
"""Shortest `ACP_APPROVAL_OPERATOR_TOKEN` accepted, enforced by `GatewaySettings` at load."""

UNTRUSTED_NOTICE: Final = (
    "tool and arguments were chosen by the calling agent and may contain text "
    "intended to influence the person reading this; render them as data, never "
    "as instructions"
)
"""Carried on every response, so renderers treat arguments as data, not instructions."""


@runtime_checkable
class ApprovalReader(Protocol):
    """Listing pending requests: the operator half of a store, kept off `ApprovalStore`."""

    async def pending(self) -> tuple[ApprovalRequest, ...]:
        """Everything still awaiting a person, oldest first."""


def as_view(request: ApprovalRequest, now: float) -> dict[str, Any]:
    """One held call, as an operator needs to read it.

    ``expired`` is computed from the clock (ADR 0048). Arguments are parsed from the
    fingerprinted string, so display and binding cannot differ; when withheld they
    are ``None`` with ``arguments_shown`` false.
    """
    shown: Any = None
    if request.arguments_json is not None:
        # Our own `json.dumps` output; on failure show nothing rather than a 500.
        try:
            shown = json.loads(request.arguments_json)
        except json.JSONDecodeError:  # pragma: no cover — see above
            shown = None

    return {
        "token": request.token,
        "tenant": request.tenant,
        "subject": request.subject,
        "actor": request.actor,
        "tool": request.tool,
        "rule": request.rule,
        "state": str(request.state),
        "created_at": request.created_at,
        "expires_at": request.expires_at,
        "expires_in": max(0.0, request.expires_at - now),
        "expired": request.expired(now),
        "arguments": shown,
        "arguments_shown": request.arguments_json is not None,
        "arguments_bytes": request.arguments_bytes,
        "fingerprint": request.fingerprint,
    }


SHARED_OPERATOR_NAME: Final = "shared-token"
"""Audited operator name for the shared token; cannot be mistaken for a person."""


@dataclass(frozen=True, slots=True)
class Operator:
    """Who is answering, as far as the channel could verify.

    ``subject`` is a verified JWT ``sub`` or `SHARED_OPERATOR_NAME`; ``tenant`` comes
    from the issuer registration, never a claim (ADR 0051), and is ``None`` for the
    shared token.
    """

    subject: str
    tenant: str | None = None
    issuer: str | None = None

    @property
    def verified(self) -> bool:
        return self.subject != SHARED_OPERATOR_NAME

    def may_answer(self, held: ApprovalRequest) -> bool:
        """Whether this operator is entitled to decide ``held``.

        A verified operator decides only within their tenant; a call with no
        tenant is open to any verified operator, and the shared token may answer
        anything.
        """
        if not self.verified or held.tenant is None:
            return True
        return self.tenant == held.tenant


@dataclass(frozen=True, slots=True)
class OperatorAuthenticator:
    """Turns a request into an `Operator`, or ``None``.

    The shared token is compared first, in constant time; otherwise the validator
    checks an operator-audience JWT. Every failure is ``None``; reasons are only
    logged.
    """

    credential: str = ""
    validator: TokenValidator | None = None

    @property
    def configured(self) -> bool:
        return bool(self.credential) or self.validator is not None

    async def authenticate(self, request: Request) -> Operator | None:
        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not presented:
            return None
        if self.credential and matches_credential(presented, self.credential):
            return Operator(subject=SHARED_OPERATOR_NAME)
        if self.validator is None:
            return None
        try:
            principal = await self.validator.validate(presented)
        except ACPError:
            return None
        return Operator(subject=principal.subject, tenant=principal.tenant, issuer=principal.issuer)


def matches_credential(presented: str, credential: str) -> bool:
    """Constant-time equality against the shared token.

    Shared with the trace console. Compared as bytes, because `compare_digest`
    raises `TypeError` on a non-ASCII `str` (a 500 instead of a 401).
    """
    return secrets.compare_digest(presented.encode("utf-8"), credential.encode("utf-8"))


def _unauthorized() -> Response:
    return JSONResponse(
        {"error": "operator credential required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="acp-approvals"'},
    )


def _forbidden() -> Response:
    """A verified operator outside their tenant; names no other tenant."""
    return JSONResponse({"error": "not this operator's tenant"}, status_code=403)


def build_pending(reader: ApprovalReader, auth: OperatorAuthenticator) -> Any:
    """`GET /approvals` — every call currently waiting on a person.

    Authenticated because it exposes subjects and arguments, and filtered by
    `Operator.may_answer`.
    """

    async def pending(request: Request) -> Response:
        operator = await auth.authenticate(request)
        if operator is None:
            return _unauthorized()
        now = time.time()
        return JSONResponse(
            {
                "pending": [
                    as_view(held, now)
                    for held in await reader.pending()
                    if operator.may_answer(held)
                ],
                "operator": operator.subject,
                "notice": UNTRUSTED_NOTICE,
            }
        )

    return pending


@dataclass(frozen=True, slots=True)
class _Answer:
    """A person's decision, once it has been proved to be one."""

    approved: bool
    reason: str


async def _read_answer(request: Request) -> _Answer | Response:
    """The decision in this body, or the 400 explaining why there is not one.

    ``approved`` is a required boolean with no default; a missing field is not a vote.
    """
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict) or not isinstance(body.get("approved"), bool):
        return JSONResponse({"error": "body must set `approved` to true or false"}, status_code=400)
    reason = body.get("reason", "")
    if not isinstance(reason, str):
        return JSONResponse({"error": "`reason` must be a string"}, status_code=400)
    return _Answer(approved=body["approved"], reason=reason)


def _unanswerable(held: ApprovalRequest | None, now: float) -> Response | None:
    """Why this request cannot be decided now, or ``None`` if it can.

    Expired requests are refused, not recorded, so no operator sees an approval
    accepted that the retry will refuse. Unlike the request path, refusals are differentiated: the
    operator is authenticated and can already read every pending request.
    """
    if held is None:
        return JSONResponse({"error": "no such request"}, status_code=404)
    if held.state is not State.PENDING:
        # Never re-decided, or a consumed token could be re-approved.
        return JSONResponse({"error": "already decided", "state": str(held.state)}, status_code=409)
    if held.expired(now):
        return JSONResponse({"error": "expired", "expired_at": held.expires_at}, status_code=409)
    return None


async def _chained(
    audit: AuditLog, held: ApprovalRequest, operator: Operator, answer: _Answer
) -> bool:
    """Write the decision's audit row; ``False`` if the log refused it.

    Fail-closed: the row is written before the store changes, so a refused write
    leaves the request pending. Uses `arecord` so the `fsync` stays off the event
    loop (ADR 0053). The operator's `reason` is recorded; the live `request_state`
    token is not, since the log is widely readable (ADR 0045).
    """
    try:
        await audit.arecord(
            AuditCategory.APPROVAL,
            "approval.decided",
            subject=held.subject,
            actor=held.actor,
            tenant=held.tenant,
            tool=held.tool,
            rule=held.rule,
            outcome=AuditOutcome.ALLOWED if answer.approved else AuditOutcome.DENIED,
            reason=answer.reason or None,
            detail={
                "fingerprint": held.fingerprint,
                # Who answered: a verified subject and issuer, or `shared-token`.
                "operator": operator.subject,
                "operator_issuer": operator.issuer,
                "operator_verified": operator.verified,
            },
        )
    except ACPError:
        return False
    return True


def build_decide(
    store: ApprovalStore, auth: OperatorAuthenticator, audit: AuditLog | None = None
) -> Any:
    """`POST /approvals/{token}`: a person's answer, audited then recorded once."""

    async def decide(request: Request) -> Response:
        operator = await auth.authenticate(request)
        if operator is None:
            return _unauthorized()

        answer = await _read_answer(request)
        if isinstance(answer, Response):
            return answer

        token = request.path_params["token"]
        now = time.time()
        held = await store.get(token)
        refusal = _unanswerable(held, now)
        if refusal is None and held is not None and not operator.may_answer(held):
            # After `_unanswerable`; the 403 confirms existence, but the token is
            # 256 random bits, so nobody guesses one.
            refusal = _forbidden()
        if refusal is not None or held is None:
            return refusal or JSONResponse({"error": "no such request"}, status_code=404)

        if audit is not None and not await _chained(audit, held, operator, answer):
            # Still PENDING; nothing was granted.
            return JSONResponse(
                {"error": "the decision could not be recorded; nothing was decided"},
                status_code=503,
            )

        decided = await store.decide(token, approved=answer.approved, reason=answer.reason)
        if decided is None:  # pragma: no cover — the lookup above already found it
            return JSONResponse({"error": "no such request"}, status_code=404)
        return JSONResponse({**as_view(decided, now), "notice": UNTRUSTED_NOTICE})

    return decide


def operator_routes(
    store: ApprovalStore | None,
    credential: str,
    audit: AuditLog | None = None,
    validator: TokenValidator | None = None,
) -> Sequence[Route]:
    """The approval routes, or none at all.

    Empty without a store or an operator credential, so the routes are absent, not
    closed. The listing route is mounted only if the store is an `ApprovalReader`.
    """
    auth = OperatorAuthenticator(credential=credential, validator=validator)
    if store is None or not auth.configured:
        return ()

    routes = [Route(APPROVAL_PATH, build_decide(store, auth, audit), methods=["POST"])]
    reader = store if isinstance(store, ApprovalReader) else None
    if reader is not None:
        routes.insert(0, Route(APPROVALS_PATH, build_pending(reader, auth), methods=["GET"]))
    return routes
