"""Resolving a retry: does this call proceed, wait, or stop?

The half of the approval flow that runs on the request path. Everything here is
a pure function of the store's contents, the clock and the call in hand — no
I/O, no MCP types, no gateway — so the whole decision table is testable by
advancing a number.

**Every branch that is not "approved, matching, fresh, unspent" refuses**, and
the refusal is undifferentiated. A caller learns that this did not work; the log
learns which of the seven reasons it was. Telling the caller "that token has
expired" versus "that token is not yours" is an oracle they can map one request
at a time — the same argument `PolicyDeniedError` makes about naming the rule,
and `AuthenticationError` makes about its logged reason.

The seven ways a retry stops:

1. **No token** — nothing to resolve.
2. **Unknown token** — expired out of the store, or invented.
3. **Expired** — the default-deny, checked here rather than by a sweeper so it
   cannot be honoured late because a background job did not run.
4. **Fingerprint mismatch** — *the call is not the one that was approved.* The
   reason this module exists; see `acp.approvals.record`.
5. **Wrong subject** — an approval is not bearer-transferable between callers.
6. **Denied** — a human said no.
7. **Consumed** — spent already. One approval, one call.

A `PENDING` request is the eighth outcome and the only one that is not a
refusal: the caller is told to wait, with the same token, and nothing changes.
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
    """Any of the seven. The caller gets an undifferentiated denial."""


@dataclass(frozen=True, slots=True)
class Resolution:
    """What happened, and why — the why for the log, not for the caller."""

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

    Split from the state checks because they answer different questions and get
    read at different times. These four are about *whether the held record is
    about the call in front of us at all* — and they are checked first, so a
    mismatched call is refused before its state is even consulted. A record that
    does not bind is not this caller's approval, whatever it says.
    """
    if held.expired(now):
        # Default-deny on expiry, and before the state, so a request approved
        # after it lapsed is still refused. "Late" is a decision the caller does
        # not get the benefit of.
        return "approval expired"
    if held.tenant != tenant:
        # Checked before the fingerprint, which would also catch it (the tenant
        # is in the digest since v2), because this refusal must not depend on a
        # hash comparison staying in the material list. Belt over braces, in
        # the direction where slipping is an escalation.
        return "approval belongs to another tenant"
    if held.subject != subject:
        return "approval belongs to another subject"
    digest = fingerprint(
        tenant=tenant, subject=subject, actor=actor, tool=tool, arguments=arguments
    )
    if digest is None:
        return "call cannot be fingerprinted"
    if digest != held.fingerprint:
        # The one that matters. A human approved a call; this is a different
        # call wearing its token.
        return "call does not match the approved one"
    return None


_STATE_REFUSALS = {
    State.DENIED: "approval was refused",
    State.CONSUMED: "approval already used",
}


def resolve(
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

    Consumes the request as part of returning ``PROCEED``, inside this function
    rather than at the call site. A caller that had to remember to spend the
    token is a caller that eventually does not, and the failure is silent: the
    same approval authorises every subsequent call until it expires.
    """
    if not token:
        return Resolution(Outcome.REFUSE, "no request_state supplied")

    held = store.get(token)
    if held is None:
        return Resolution(Outcome.REFUSE, "unknown request_state")

    failure = _binding_failure(
        held, tenant=tenant, subject=subject, actor=actor, tool=tool, arguments=arguments, now=now
    )
    if failure is not None:
        return Resolution(Outcome.REFUSE, failure, held)

    if held.state is State.PENDING:
        return Resolution(Outcome.WAIT, "awaiting a decision", held)
    refusal = _STATE_REFUSALS.get(held.state)
    if refusal is not None:
        return Resolution(Outcome.REFUSE, refusal, held)

    store.consume(token)
    return Resolution(Outcome.PROCEED, "approved", held)


# ---------------------------------------------------------------------------
# The request path's whole decision, in one pure function
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Gate:
    """What the gateway should do about a call the policy held.

    Everything the request path needs and nothing about MCP: the handler turns
    this into an `InputRequiredResult` or an error, and this module never learns
    what those are. The same split as `enforce_call` — the decision here, the
    protocol at the one call site.
    """

    outcome: Outcome
    reason: str
    token: str | None = None
    """The `request_state` to hand back. Present on `WAIT`, and on a first ask
    it is a *new* token; on a poll it is the same one, unchanged."""

    expires_at: float | None = None
    """When the caller stops being able to answer.

    Safe to disclose for the reason `retry_after` is (task 42): it describes only
    the limit the caller is already inside. It is a hint, not a promise — the
    check that matters happens at resolution.
    """


def gate(
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

    Two paths, and which one runs is decided by whether the caller sent a token
    — *not* by whether one exists for this call. Looking up a pending request by
    fingerprint instead would let one caller's poll attach to another's approval,
    and would make the token decorative.

    A caller who loses their token simply asks again and gets a second pending
    request. That is the right behaviour and it is why the store is bounded: the
    cost of forgetting is a re-ask, and the cost of doing it in a loop is
    eviction rather than the process.
    """
    if token:
        resolution = resolve(
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
            # The same token, unchanged. A poll that minted a new one would
            # leave the old request pending and approvable — an operator's yes
            # landing on a token nobody is holding any more.
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
        # Unfingerprintable arguments. Refused rather than held, because an
        # approval that cannot be bound to a call is an approval for anything.
        return Gate(Outcome.REFUSE, "call cannot be fingerprinted")
    store.create(request)
    return Gate(Outcome.WAIT, "approval requested", request.token, request.expires_at)
