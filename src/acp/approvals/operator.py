"""The channel a human answers on, and why it is not the one the agent speaks to.

Task 55. Task 54 built everything up to the moment a call stops: the policy says
`require_approval`, the gateway answers `input_required`, and the record sits in
the store waiting. Nothing could answer it. This is the answering.

**The separation is the feature, not the plumbing.** The agent talks to the MCP
listener on `:8080`; a person decides on the admin listener on `:9090`, which is
bound to loopback by default and has never been reachable from the request path.
So an agent cannot approve its own call *because it cannot address the thing that
approves calls* — a structural property rather than a check somebody has to
remember to write. It is the same argument `_await_approval` makes about
`input_responses` (MRTR lets a client answer the questions a server asked, and
here the client is the agent), made once more in the network topology, because a
control that depends on one `if` statement staying correct is a control one
refactor away from being gone.

**These endpoints are authenticated, and the rest of the admin surface is not.**
That surface was designed as a read-only scrape target behind loopback. Approving
a call is a *write*, and the thing it writes is a permission — so the channel is
mounted only when an operator credential is configured, and a deployment that has
not configured one does not get a 403, it gets a listener with no such route.
A feature you did not configure should not exist; a 403 is a promise that the
thing is there and merely shut, which invites exactly one more mistake.

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

APPROVALS_PATH: Final = "/approvals"
APPROVAL_PATH: Final = "/approvals/{token}"

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

    def pending(self) -> tuple[ApprovalRequest, ...]:
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
        "subject": request.subject,
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


def _authorized(request: Request, credential: str) -> bool:
    """Whether this request carries the operator credential.

    ``compare_digest`` rather than ``==``: the comparison is against a secret,
    and a short-circuiting comparison over a value an attacker controls leaks its
    prefix one request at a time. Cheap to do correctly, and this is a listener
    somebody will eventually expose beyond loopback whatever the default says.
    """
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return secrets.compare_digest(presented, credential)


def _unauthorized() -> Response:
    return JSONResponse(
        {"error": "operator credential required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="acp-approvals"'},
    )


def build_pending(reader: ApprovalReader, credential: str) -> Any:
    """`GET /approvals` — every call currently waiting on a person.

    Authenticated even though it only reads, because of *what* it reads. The list
    carries subjects, tool names and argument values: it is a live feed of what
    the estate's agents are trying to do, which is a better reconnaissance report
    than the metrics endpoint this listener was designed around.
    """

    async def pending(request: Request) -> Response:
        if not _authorized(request, credential):
            return _unauthorized()
        now = time.time()
        return JSONResponse(
            {
                "pending": [as_view(held, now) for held in reader.pending()],
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


def build_decide(store: ApprovalStore, credential: str) -> Any:
    """`POST /approvals/{token}` — a person's answer, recorded once."""

    async def decide(request: Request) -> Response:
        if not _authorized(request, credential):
            return _unauthorized()

        answer = await _read_answer(request)
        if isinstance(answer, Response):
            return answer

        token = request.path_params["token"]
        now = time.time()
        refusal = _unanswerable(store.get(token), now)
        if refusal is not None:
            return refusal

        decided = store.decide(token, approved=answer.approved, reason=answer.reason)
        if decided is None:  # pragma: no cover — the lookup above already found it
            return JSONResponse({"error": "no such request"}, status_code=404)
        return JSONResponse({**as_view(decided, now), "notice": UNTRUSTED_NOTICE})

    return decide


def operator_routes(store: ApprovalStore | None, credential: str) -> Sequence[Route]:
    """The approval routes, or none at all.

    Two ways to get an empty list, and they are the same answer to different
    questions: nothing to decide about (no store), or nobody entitled to decide
    (no credential). Either way the routes are absent rather than present and
    closed — see the module docstring.

    ``reader`` is narrowed by capability rather than by type. A store that cannot
    list is a perfectly good request-path store, and it simply does not get a
    listing endpoint; that is a smaller failure than refusing to mount a channel
    an operator could still use to answer a token they were told about.
    """
    if store is None or not credential:
        return ()

    routes = [Route(APPROVAL_PATH, build_decide(store, credential), methods=["POST"])]
    reader = store if isinstance(store, ApprovalReader) else None
    if reader is not None:
        routes.insert(0, Route(APPROVALS_PATH, build_pending(reader, credential), methods=["GET"]))
    return routes
