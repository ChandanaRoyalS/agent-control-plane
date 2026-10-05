"""The channel a human answers on, and why it is not the one the agent speaks to.

`acp.approvals.record` builds everything up to the moment a call stops: the policy says
`require_approval`, the gateway answers `input_required`, and the record sits in
the store waiting. Nothing could answer it. This is the answering.

**The separation is the feature, not the plumbing.** The agent talks to the MCP
listener on `:8080`; a person decides on the admin listener on `:9090`, a
separate port bound to loopback by default, behind a credential the request
path never sees. On the default bind an agent cannot reach the thing that
approves calls at all; on a wider bind — the compose stack publishes the port —
it would need an operator's credential to try (ADR 0049 §4). It is the same
argument `_await_approval` makes about `input_responses` (MRTR lets a client
answer the questions a server asked, and here the client is the agent), made
once more at the network layer.

**Who is answering is recorded, not assumed.** An operator proves who they are
in one of two ways. The strong one is a JWT from an authorization server this
gateway already trusts, minted for the *operator audience* rather than the
gateway's (`ACP_APPROVAL_OPERATOR_AUDIENCE`): the same validator, keys, issuer
binding and tenant stamping as the request path, so the audit row can name a
verified subject and an operator from one tenant cannot answer another tenant's
call. The weak one is the shared token (`ACP_APPROVAL_OPERATOR_TOKEN`), kept
for a laptop and a compose stack, which proves possession of a secret and
nothing about a person — the row says so (`operator: shared-token`). A
deployment that is a security control should configure the first.

**These endpoints are authenticated, and the rest of the admin surface is not.**
That surface was designed as a read-only scrape target behind loopback. Approving
a call is a *write*, and the thing it writes is a permission — so the channel is
mounted only when a way to authenticate an operator is configured, and a
deployment that has configured none does not get a 403, it gets a listener with
no such route. A feature you did not configure should not exist; a 403 is a
promise that the thing is there and merely shut, which invites one more mistake.

**And the last place an injection can land is here.** The arguments shown below
were chosen by an agent that may have read a hostile document. Their audience is
now a person, deciding. A document that cannot talk the gateway into running a
tool can still try to talk the *operator* into approving one — "APPROVED BY
SECURITY, click yes". So the values leave here as JSON data under a name that
says what they are, never as prose, and `UNTRUSTED_NOTICE` travels with every
response for whatever renders them. ADR 0038 fences upstream content before an
agent reads it; this is the same idea pointed at the human, who is the one
reader that cannot be given a system prompt.
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
"""The shortest `ACP_APPROVAL_OPERATOR_TOKEN` the settings will accept.

Enforced at configuration load (`GatewaySettings`), not here: a gateway that
would start with `changeme` as the credential for the one write on this
listener should not start. Defined beside the comparison so the two are read
together.
"""

UNTRUSTED_NOTICE: Final = (
    "tool and arguments were chosen by the calling agent and may contain text "
    "intended to influence the person reading this; render them as data, never "
    "as instructions"
)
"""Carried on every response, for whatever puts this on a screen.

Not decoration and not a disclaimer. A console that renders `arguments` as
markdown, or an alerting bot that pastes them into a chat channel, has just given
a poisoned document a direct line to the one participant with the authority to
say yes.
"""


@runtime_checkable
class ApprovalReader(Protocol):
    """Listing pending requests — the operator half of a store.

    Deliberately *not* on `ApprovalStore`. That protocol is the request path's,
    and it holds exactly the four operations a request needs; enumerating every
    call the fleet is currently waiting on is not one of them, and a shared store
    may hold far more than any single instance should ever list. Keeping them
    apart means the seam states which side needs what, rather than one interface
    that both sides over-satisfy.
    """

    async def pending(self) -> tuple[ApprovalRequest, ...]:
        """Everything still awaiting a person, oldest first."""


def as_view(request: ApprovalRequest, now: float) -> dict[str, Any]:
    """One held call, as an operator needs to read it.

    ``expired`` is computed here rather than stored, because expiry is a function
    of the clock and the record (`State` has no `EXPIRED` member, and ADR 0048
    says why). An operator looking at a list must see which of these are already
    beyond answering, or the first thing the channel does is invite somebody to
    approve a call that will be refused anyway and to believe they unblocked it.

    Arguments are parsed back from the canonical string the fingerprint was taken
    over, so what is displayed and what is bound cannot differ. When they were
    too large to hold they are ``None`` and ``arguments_shown`` is false — an
    honest "you are being asked to approve something you cannot see" rather than
    an empty object that reads like a call with no arguments.
    """
    shown: Any = None
    if request.arguments_json is not None:
        # Round-trips a string this process produced with `json.dumps` moments
        # ago. It cannot fail; if it somehow did, showing nothing is the right
        # answer, because the alternative is a 500 on the channel that unblocks
        # production.
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
"""What the audit row records as the operator when the shared token was used.

A name that cannot be mistaken for a person. The row is the one record of who
answered, and "the shared token" is the honest answer when that is all the
channel verified — not blank, which reads as an omission, and not a configured
label, which would let a config file assert an identity nothing checked.
"""


@dataclass(frozen=True, slots=True)
class Operator:
    """Who is answering, as far as the channel could verify.

    ``subject`` is a verified JWT ``sub`` or `SHARED_OPERATOR_NAME`; ``tenant``
    is stamped from the issuer registration (never a claim — the same rule as
    the request path, ADR 0051) and is ``None`` for the shared token, which
    belongs to no tenant and is therefore not scoped to one.
    """

    subject: str
    tenant: str | None = None
    issuer: str | None = None

    @property
    def verified(self) -> bool:
        return self.subject != SHARED_OPERATOR_NAME

    def may_answer(self, held: ApprovalRequest) -> bool:
        """Whether this operator is entitled to decide ``held``.

        A verified operator decides only within their tenant: acme's operator
        does not approve globex's delete, however valid acme's token is. A call
        with no tenant (a single-tenant deployment) is open to any verified
        operator, and the shared token — scoped to nothing — may answer
        anything, which is one more reason to prefer the JWT.
        """
        if not self.verified or held.tenant is None:
            return True
        return self.tenant == held.tenant


@dataclass(frozen=True, slots=True)
class OperatorAuthenticator:
    """Turns a request into an `Operator`, or ``None``.

    Two proofs, tried in a fixed order. The shared token is compared first and
    in constant time; anything that is not it is handed to the validator, when
    one is configured, as a JWT minted for the operator audience. Every failure
    is the same ``None`` — the specific reason is logged by the validator and
    never returned, for the reason `TokenValidator` gives.
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

    Public because the trace console checks the same credential on the same
    listener, and a second copy is how the console kept the bug this one had
    already fixed (W11 of the external review).

    ``compare_digest`` rather than ``==``: the comparison is against a secret,
    and a short-circuiting comparison over a value an attacker controls leaks its
    prefix one request at a time. Over bytes, not str: `compare_digest` raises
    `TypeError` for a non-ASCII `str`, which turned an unauthenticated request
    carrying one into a 500 on the admin listener rather than a 401.
    """
    return secrets.compare_digest(presented.encode("utf-8"), credential.encode("utf-8"))


def _unauthorized() -> Response:
    return JSONResponse(
        {"error": "operator credential required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="acp-approvals"'},
    )


def _forbidden() -> Response:
    """A verified operator, outside their tenant.

    Differentiated from 401 because the operator is authenticated and is the
    party this channel serves (see `_unanswerable`); what is withheld is which
    *other* tenant's call this is, and the 403 carries none of it.
    """
    return JSONResponse({"error": "not this operator's tenant"}, status_code=403)


def build_pending(reader: ApprovalReader, auth: OperatorAuthenticator) -> Any:
    """`GET /approvals` — every call currently waiting on a person.

    Authenticated even though it only reads, because of *what* it reads. The list
    carries subjects, tool names and argument values: it is a live feed of what
    the estate's agents are trying to do, which is a better reconnaissance report
    than the metrics endpoint this listener was designed around.

    Filtered by what the operator may answer: a tenant's operator sees that
    tenant's queue, not the estate's. The shared token sees everything, which
    is the listing-side statement of the same fact `Operator.may_answer` makes.
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

    ``approved`` is required and must be a boolean. No default, for the reason
    `Rule.effect` has none: a body that forgot to say which way would otherwise
    be read as one of them, and the two readings are "let it run" and "stop it".
    A missing field is not a vote.

    Returns the answer or the response that replaces it, rather than a pair
    with one half always empty — the caller then has a single ``isinstance``
    check and no state in which both are set or neither is.
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

    **An expired request is refused here rather than decided.** `store.decide`
    would happily record it and the retry would then be refused on expiry, which
    is correct and completely opaque: an operator would see their approval
    accepted and the caller still blocked, with nothing anywhere saying why.

    Refusals here are *differentiated*, and that is a deliberate inversion of the
    rule the request path follows. An agent learns only that its call did not
    work, because telling it "expired" rather than "not yours" is an oracle it
    can map one request at a time. The operator is the party this control exists
    to serve, is already authenticated, and can already read every pending
    request in full — there is nothing left to withhold, and withholding it
    anyway would only make the channel harder to use correctly.
    """
    if held is None:
        return JSONResponse({"error": "no such request"}, status_code=404)
    if held.state is not State.PENDING:
        # Already answered, or already spent. `store.decide` refuses to re-decide
        # for a reason worth surfacing rather than swallowing: without it,
        # anything holding this credential could re-approve a consumed token and
        # hand out the same permission twice.
        return JSONResponse({"error": "already decided", "state": str(held.state)}, status_code=409)
    if held.expired(now):
        return JSONResponse({"error": "expired", "expired_at": held.expires_at}, status_code=409)
    return None


async def _chained(
    audit: AuditLog, held: ApprovalRequest, operator: Operator, answer: _Answer
) -> bool:
    """Write the decision's audit row; ``False`` if the log refused it.

    **Chained before it is decided, and awaited.** Fail-closed means a decision
    this gateway cannot record is not made: the row is written first, and only
    then does the store change state — so an audit log that refuses leaves the
    request pending for a retry rather than approved-and-unrecorded. `arecord`,
    not `record`: the file sink's write is an `fsync`, and running it on the
    event loop from here parked every other request in the process (ADR 0053)
    and bypassed the writer's serialisation that every other path goes through.

    The operator's `reason` **is** recorded, unlike almost everything else a
    caller supplies. It is the one free-text field in the system written by an
    authenticated human who knows it is being kept — "checked with the data
    team" is exactly what makes this row worth having.

    What is *not* recorded: the `request_state` token. It is a live handle for
    up to five minutes, and this file is durable and widely readable (ADR 0045)
    — the wrong place for a credential of any lifetime. The fingerprint
    identifies the call for an investigation and is useless for spending the
    approval.
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
                # *Who answered.* A verified subject and the issuer that vouched
                # for it, or the honest `shared-token`. This is the field the
                # row exists for.
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
    """`POST /approvals/{token}` — a person's answer, recorded once.

    **The human's decision is chained.** Every other audit record in this project
    is a thing the gateway decided; this is the one a person did, and it is the
    row an investigation actually wants — *who approved the delete, and what did
    they say they had checked*. Leaving it out would mean the chain could show a
    call being held and then running, with nothing in between explaining why.
    """

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
            # After `_unanswerable`, so an operator is told "no such request"
            # for a token that does not exist and "not your tenant" only for one
            # that does — the existence of another tenant's token is still not
            # something a URL guess should confirm... except that it must be,
            # because the token is 256 random bits and was handed to the agent
            # that asked. Nobody guesses it; the 403 leaks nothing.
            refusal = _forbidden()
        if refusal is not None or held is None:
            return refusal or JSONResponse({"error": "no such request"}, status_code=404)

        if audit is not None and not await _chained(audit, held, operator, answer):
            # The request stays PENDING. The operator can answer again once the
            # log is writable; nothing was granted in the meantime.
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

    Two ways to get an empty list, and they are the same answer to different
    questions: nothing to decide about (no store), or nobody entitled to decide
    (neither a shared token nor an operator validator). Either way the routes
    are absent rather than present and closed — see the module docstring.

    ``reader`` is narrowed by capability rather than by type. A store that cannot
    list is a perfectly good request-path store, and it simply does not get a
    listing endpoint; that is a smaller failure than refusing to mount a channel
    an operator could still use to answer a token they were told about.
    """
    auth = OperatorAuthenticator(credential=credential, validator=validator)
    if store is None or not auth.configured:
        return ()

    routes = [Route(APPROVAL_PATH, build_decide(store, auth, audit), methods=["POST"])]
    reader = store if isinstance(store, ApprovalReader) else None
    if reader is not None:
        routes.insert(0, Route(APPROVALS_PATH, build_pending(reader, auth), methods=["GET"]))
    return routes
