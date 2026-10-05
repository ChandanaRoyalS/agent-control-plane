"""Resolving a retry on the request path: does this call proceed, wait, or stop?

Depends only on the store, the clock and the call (no MCP types). Anything but
approved, matching, fresh and unspent is refused, and the caller gets one
undifferentiated refusal so it is not an oracle; only the log records why (no or
unknown token, expired, other tenant or subject, fingerprint mismatch, denied,
consumed). A `PENDING` request answers wait, with the same token.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from acp.approvals.record import (
    DEFAULT_TTL_SECONDS,
    ApprovalRequest,
    State,
    fingerprint,
    request_for,
)
from acp.approvals.store import ApprovalStore


class Outcome(StrEnum):
    """What the request path should do next."""

    PROCEED = "proceed"
    """Approved, matching, fresh, and now spent. Execute the call."""

    WAIT = "wait"
    """Still pending. Answer `input_required` again with the same token."""

    REFUSE = "refuse"
    """Any refusal; the caller gets an undifferentiated denial."""


@dataclass(frozen=True, slots=True)
class Resolution:
    """What happened, and why (the why is for the log, not the caller)."""

    outcome: Outcome
    reason: str
    request: ApprovalRequest | None = None

    @property
    def proceed(self) -> bool:
        return self.outcome is Outcome.PROCEED


def _binding_failure(
    held: ApprovalRequest,
    *,
    tenant: str | None,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, Any],
    now: float,
) -> str | None:
    """Why this token does not bind to this call, or ``None`` if it does.

    Checked before the record's state, so a mismatched call is refused regardless.
    """
    if held.expired(now):
        # Before the state, so an approval given after expiry is still refused.
        return "approval expired"
    if held.tenant != tenant:
        # Explicit, not left to the fingerprint alone, so it cannot regress.
        return "approval belongs to another tenant"
    if held.subject != subject:
        return "approval belongs to another subject"
    digest = fingerprint(
        tenant=tenant, subject=subject, actor=actor, tool=tool, arguments=arguments
    )
    if digest is None:
        return "call cannot be fingerprinted"
    if digest != held.fingerprint:
        # A different call wearing the approved call's token.
        return "call does not match the approved one"
    return None


_STATE_REFUSALS = {
    State.APPROVED: "approval already used",  # approved when read, spent before we could
    State.DENIED: "approval was refused",
    State.CONSUMED: "approval already used",
}


async def resolve(
    store: ApprovalStore,
    token: str | None,
    *,
    tenant: str | None,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, Any],
    now: float,
) -> Resolution:
    """Decide what to do with a retry carrying ``token``.

    Spends the approval itself before returning ``PROCEED``, so no call site can
    forget to.
    """
    if not token:
        return Resolution(Outcome.REFUSE, "no request_state supplied")

    held = await store.get(token)
    if held is None:
        return Resolution(Outcome.REFUSE, "unknown request_state")

    failure = _binding_failure(
        held, tenant=tenant, subject=subject, actor=actor, tool=tool, arguments=arguments, now=now
    )
    if failure is not None:
        return Resolution(Outcome.REFUSE, failure, held)

    if held.state is State.PENDING:
        return Resolution(Outcome.WAIT, "awaiting a decision", held)

    # `consume` is compare-and-set: of racing retries exactly one proceeds.
    spent = held.state is State.APPROVED and await store.consume(token)
    if not spent:
        return Resolution(Outcome.REFUSE, _STATE_REFUSALS[held.state], held)
    return Resolution(Outcome.PROCEED, "approved", held)


# The request path's whole decision


@dataclass(frozen=True, slots=True)
class Gate:
    """What the gateway should do about a held call; the handler maps it to MCP."""

    outcome: Outcome
    reason: str
    token: str | None = None
    """The `request_state` on `WAIT`: new on a first ask, unchanged on a poll."""

    expires_at: float | None = None
    """When the request expires; a hint safe to disclose, enforced at resolution."""


async def gate(
    store: ApprovalStore,
    *,
    token: str | None,
    tenant: str | None,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, Any],
    rule: str | None,
    now: float,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> Gate:
    """Start an approval, or resolve the one this retry carries.

    The path depends only on whether the caller sent a token, never on a lookup by
    fingerprint, which could attach one caller's poll to another's approval. A
    caller without a token gets a new pending request.
    """
    if token:
        resolution = await resolve(
            store,
            token,
            tenant=tenant,
            subject=subject,
            actor=actor,
            tool=tool,
            arguments=arguments,
            now=now,
        )
        held = resolution.request
        if resolution.outcome is Outcome.WAIT:
            # Same token: a new one would leave the old request approvable.
            return Gate(Outcome.WAIT, resolution.reason, token, held.expires_at if held else None)
        return Gate(resolution.outcome, resolution.reason)

    request = request_for(
        tenant=tenant,
        subject=subject,
        actor=actor,
        tool=tool,
        arguments=arguments,
        rule=rule,
        now=now,
        ttl=ttl,
    )
    if request is None:
        # Unbindable, so refused: it would be an approval for anything.
        return Gate(Outcome.REFUSE, "call cannot be fingerprinted")
    await store.create(request)
    return Gate(Outcome.WAIT, "approval requested", request.token, request.expires_at)
