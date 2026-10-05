"""Where pending approvals live, behind a seam.

The in-memory default is correct for a single instance only;
`acp.approvals.redis_store` is the shared one (ADR 0066), selected by
`ACP_APPROVAL_STORE_URL`. The protocol is async so no blocking store can be wired
onto the event loop (ADR 0053). The token is an opaque handle and the decision stays
server-side, since a client-carried decision could be minted and could not be
revoked or spent once.
"""

from __future__ import annotations

from typing import Protocol

from acp.approvals.record import ApprovalRequest, State

DEFAULT_MAX_PENDING = 256
"""Ceiling on held requests, so a caller cannot exhaust memory with asks."""


class ApprovalStore(Protocol):
    """The four operations an approval flow needs.

    No general `put`, so the request path cannot write an `APPROVED` record;
    only the operator side calls `decide`.
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
        """Spend an ``APPROVED`` record, once. ``True`` only for the call that spent it.

        Compare-and-set: of concurrent retries, exactly one gets ``True``; the
        others must refuse.
        """


class InMemoryApprovalStore:
    """Pending approvals in an insertion-ordered dict, bounded; single instance only.

    Eviction order is a security property, so a flood cannot evict another
    principal's decision. When full, evict in order: anything expired; anything
    decided or consumed; the incoming principal's oldest pending request; only then
    the oldest pending overall.
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
            # Never re-decide, or a spent token could be re-approved.
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
        """Everything still awaiting a person, oldest first (operator side; not in the protocol)."""
        return tuple(
            request for request in self._pending.values() if request.state is State.PENDING
        )
