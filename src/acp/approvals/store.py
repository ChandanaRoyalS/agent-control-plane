"""Where pending approvals live, behind a seam.

**The honest cut, stated first.** The shipped store is in memory, per process —
and unlike the rate limiter's identical cut (ADR 0032, ADR 0044), this one
affects *correctness* rather than accuracy. A replicated gateway that answers
`input_required` from one instance and receives the retry on another cannot
resolve the token, and the caller sees a refusal for a call a human approved.

That is a real limitation and it is why `ApprovalStore` is a protocol with three
methods and no assumptions about locality. The Redis or Postgres implementation
is a class, not a redesign: `create`, `get`, `decide` and `consume` are the same
four operations against a shared row. Nothing above this module knows where the
record is.

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

    def create(self, request: ApprovalRequest) -> None:
        """Hold a new pending request."""

    def get(self, token: str) -> ApprovalRequest | None:
        """The request for this token, or ``None`` if there is not one."""

    def decide(self, token: str, *, approved: bool, reason: str = "") -> ApprovalRequest | None:
        """Record a human's answer. ``None`` if the token is unknown."""

    def consume(self, token: str) -> None:
        """Mark an approval spent. Called once, when the retry proceeds."""


class InMemoryApprovalStore:
    """Pending approvals in a dict, bounded, oldest evicted first.

    Correct for a single instance and honest about being so — see the module
    docstring. Insertion-ordered, which Python dictionaries guarantee, so
    eviction is `next(iter(...))` rather than a scan for the oldest timestamp:
    the two agree because a request's `created_at` only ever increases.
    """

    def __init__(self, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        self._max_pending = max_pending

    def create(self, request: ApprovalRequest) -> None:
        while len(self._pending) >= self._max_pending:
            self._pending.pop(next(iter(self._pending)))
        self._pending[request.token] = request

    def get(self, token: str) -> ApprovalRequest | None:
        return self._pending.get(token)

    def decide(self, token: str, *, approved: bool, reason: str = "") -> ApprovalRequest | None:
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

    def consume(self, token: str) -> None:
        held = self._pending.get(token)
        if held is not None:
            self._pending[token] = held.consumed()

    def __len__(self) -> int:
        return len(self._pending)

    def pending(self) -> tuple[ApprovalRequest, ...]:
        """Everything still awaiting a person, oldest first.

        For the operator side (task 55) and for tests. Not part of the protocol:
        a shared store may hold far more than one instance should ever list, and
        the request path never needs it.
        """
        return tuple(
            request for request in self._pending.values() if request.state is State.PENDING
        )
