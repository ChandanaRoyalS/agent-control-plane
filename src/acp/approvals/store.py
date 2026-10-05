"""Where pending approvals live, behind a seam.

**Two stores, one protocol.** The default is in memory, per process — correct
for a single instance and nothing else: a replicated gateway that answers
`input_required` from one instance and receives the retry on another cannot
resolve the token, and the caller sees a refusal for a call a human approved.
`acp.approvals.redis_store` is the shared one (ADR 0066), selected by
`ACP_APPROVAL_STORE_URL`. `create`, `get`, `decide` and `consume` are the same
four operations against a shared row, and nothing above this module knows where
the record is.

**The protocol is async because one of its implementations talks to a network.**
The in-memory store never awaits anything; it carries the `async` so the request
path has one call shape and a store that *does* block cannot be wired in by
accident on the event loop (ADR 0053).

**Why the state cannot live in the token instead.** A self-contained signed token
would make the gateway genuinely stateless, and it is wrong. The approval
*decision* is the thing being protected, and a decision carried by the client is
a decision the client can mint. Even leaving forgery aside, a self-contained
token cannot be revoked and cannot be spent once — both of which this flow
requires. So the token is an opaque handle and the record is server-side, and the
gateway stays stateless in the sense ADR 0001 committed to: no session, no
handshake, no sticky routing *for the protocol*. An approval is durable business
state, like a row in a database, and calling it session state to preserve a
slogan would be dishonest about what it is.
"""

from __future__ import annotations

from typing import Protocol

from acp.approvals.record import ApprovalRequest, State

DEFAULT_MAX_PENDING = 256
"""Ceiling on held requests, and a security limit before a memory one.

An authenticated caller whose policy holds a tool for approval can start one
request per call, and nothing obliges them to retry. A bound turns "fill the
gateway's memory" into "evict the oldest pending request", which costs somebody
a re-ask rather than the process. Lower than the result cache's 512 because an
approval that nobody has answered within 256 further requests was not going to
be answered.
"""


class ApprovalStore(Protocol):
    """The four operations an approval flow needs.

    Deliberately not a general key-value interface. A store that exposed `put`
    would let a caller write an `APPROVED` record directly, and the one thing
    this module must not permit is granting an approval from the request path.
    `decide` is the only way in, and it is called by the operator side.
    """

    async def create(self, request: ApprovalRequest) -> None:
        """Hold a new pending request."""

    async def get(self, token: str) -> ApprovalRequest | None:
        """The request for this token, or ``None`` if there is not one."""

    async def decide(
        self, token: str, *, approved: bool, reason: str = ""
    ) -> ApprovalRequest | None:
        """Record a human's answer. ``None`` if the token is unknown."""

    async def consume(self, token: str) -> bool:
        """Spend an approval. ``True`` if this call was the one that spent it.

        Only an ``APPROVED`` record is spent, and only once: a store shared
        between replicas can see two retries carrying the same approved token
        at the same moment, and exactly one of them may proceed. The caller
        that gets ``False`` refuses — the approval has already been used.
        """


class InMemoryApprovalStore:
    """Pending approvals in a dict, bounded, with an eviction order that
    cannot be aimed at somebody else.

    Correct for a single instance and honest about being so — see the module
    docstring. Insertion-ordered, which Python dictionaries guarantee, so "the
    oldest" is `next(iter(...))` rather than a scan: the two agree because a
    request's `created_at` only ever increases.

    **Eviction order is a security property.** The first version evicted the
    oldest entry regardless of state or owner, which meant any authenticated
    caller with one gated tool could issue `max_pending` asks and push a
    colleague's *pending* request — or an *approved* one, waiting for its retry
    — out of the store. Denial of service, not escalation, but a control that
    lets one tenant's agent cancel another tenant's human decision is not the
    control it claims to be. So, when full, in this order:

    1. anything already expired at the moment of the new request;
    2. anything already decided or consumed — these are finished and are kept
       only so a late retry gets "already decided" rather than "no such
       request";
    3. the **new request's own principal's** oldest pending request, so a
       flood evicts the flooder;
    4. only then the oldest pending request overall.
    """

    def __init__(self, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        self._max_pending = max_pending

    async def create(self, request: ApprovalRequest) -> None:
        while len(self._pending) >= self._max_pending:
            self._pending.pop(self._victim(request))
        self._pending[request.token] = request

    def _victim(self, incoming: ApprovalRequest) -> str:
        """The token to evict so that ``incoming`` fits. See the class docstring."""
        now = incoming.created_at
        held = self._pending.values()
        for pick in (
            lambda r: r.expired(now),
            lambda r: r.state is not State.PENDING,
            lambda r: r.tenant == incoming.tenant and r.subject == incoming.subject,
        ):
            for request in held:
                if pick(request):
                    return request.token
        return next(iter(self._pending))

    async def get(self, token: str) -> ApprovalRequest | None:
        return self._pending.get(token)

    async def decide(
        self, token: str, *, approved: bool, reason: str = ""
    ) -> ApprovalRequest | None:
        held = self._pending.get(token)
        if held is None:
            return None
        if held.state is not State.PENDING:
            # Already decided or already spent. Refusing to re-decide is what
            # makes `consume` meaningful: without it, an operator (or anything
            # holding the operator's credential) could re-approve a spent token
            # and hand out the same permission twice.
            return held
        decided = held.decided(approved=approved, reason=reason)
        self._pending[token] = decided
        return decided

    async def consume(self, token: str) -> bool:
        held = self._pending.get(token)
        if held is None or held.state is not State.APPROVED:
            return False
        self._pending[token] = held.consumed()
        return True

    def __len__(self) -> int:
        return len(self._pending)

    async def pending(self) -> tuple[ApprovalRequest, ...]:
        """Everything still awaiting a person, oldest first.

        For the operator side and for tests. Not part of the protocol:
        a shared store may hold far more than one instance should ever list, and
        the request path never needs it.
        """
        return tuple(
            request for request in self._pending.values() if request.state is State.PENDING
        )
