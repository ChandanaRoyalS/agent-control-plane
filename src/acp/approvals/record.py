"""What a pending approval is, and what it is bound to.

Task 54. The policy can now say `require_approval` (ADR 0048), which means a
call stops mid-flight and waits for a person. The 2026-07-28 revision gives that
a stateless-looking shape: the gateway answers `resultType: "input_required"`
with an opaque `request_state`, and the client retries with it once the approval
lands. No session, no sticky routing, no held connection.

**The one idea this module exists for: an approval is granted to a *call*, not
to a token.**

The obvious implementation stores "token X is approved" and lets the retry
through. That is a privilege escalation with extra steps. An agent asks to delete
the test dataset, a human reads "delete the test dataset" and approves, and the
agent retries the same token with `dataset=production`. Nothing in the protocol
stops it; the approval was for a token, and the token is what came back.

So every request records a **fingerprint** of exactly what was asked — who asked,
which tool, which arguments — and the retry is re-fingerprinted and compared. An
approval that does not match the call in front of it is not an approval. This is
the same failure the result cache key exists to prevent (ADR 0035), pointing the
other way: there, too broad a key serves one caller's data to another; here, too
broad a fingerprint lets one caller's approval authorise a different call.

**Why not reuse the cache's key.** Same shape, opposite failure direction. A
cache key that is too *narrow* costs a miss; an approval fingerprint that is too
*narrow* costs a re-ask, which is a nuisance. A cache key that is too *broad*
leaks; an approval fingerprint that is too *broad* escalates. Sharing one
implementation would mean a change made for the cache's failure direction
silently applies to the other, so they carry separate version stamps and evolve
apart on purpose.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Final

FINGERPRINT_VERSION: Final = "acp-approval-v2"
"""Stamped into every fingerprint. v2 added the tenant (task 58): without it,
an approval granted to acme's alice would bind to a byte-identical call from
globex's alice — a human's yes crossing a boundary the human was never shown.
The bump invalidates nothing at rest (approvals live minutes, in memory) and is
kept for the discipline: what "the same call" means can change
without an in-flight approval being reinterpreted under the new rule."""

TOKEN_BYTES: Final = 32
"""256 bits from `secrets`. The token is the only thing standing between a
caller and somebody else's pending approval, so it is generated the way a
credential is and never derived from the call it belongs to — a token an
attacker can compute from a request they can guess is not a token."""

DEFAULT_TTL_SECONDS: Final = 300.0
"""How long a request waits before it is refused.

Five minutes: long enough for somebody watching a channel, short enough that a
forgotten request does not sit approvable for an afternoon. The expiry is not a
cleanup detail — **it is the default-deny**, and it is enforced when the token is
resolved rather than by a sweeper, so an approval cannot be honoured late because
a background job did not run.
"""

MAX_DISPLAYED_ARGUMENT_BYTES: Final = 8192
"""How much of a call an operator is shown before it is withheld as too large.

A bound rather than a truncation, and the difference is the whole point. What
the operator reads is byte-identical to what the fingerprint was taken over, so
a truncated display would be a *different* call from the one being approved —
the exact confusion this module exists to prevent, reintroduced in the one place
a human is looking. Past the bound the arguments are withheld entirely and the
response says so, which makes approving blind a visible choice rather than an
accident.

Eight kilobytes because a tool call is arguments, not a payload, and because
this is multiplied by `DEFAULT_MAX_PENDING`: 256 held requests at 8 KiB is two
megabytes of worst case, which is a bound worth having.
"""


class State(StrEnum):
    """Where a request has got to.

    No `EXPIRED` member, deliberately. Expiry is a function of the clock and the
    record, not a state somebody has to transition it into — a stored `EXPIRED`
    would be a claim that something ran on time, and the whole point is that the
    answer must be right even when nothing did.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    """Used once and spent. An approval that stays approved is one approval and
    unbounded deletes."""


def canonical(arguments: Mapping[str, Any]) -> str | None:
    """The one encoding of ``arguments`` that everything else agrees on.

    Keys sorted and whitespace removed, so two spellings of one call produce one
    string. ``None`` when the value carries something JSON cannot represent —
    and the caller must **refuse**, never fall back. A `repr()` or `str()`
    fallback can map two different argument sets onto one string, which here is
    not a cache collision but a human's yes applied to a call they never saw.

    Extracted so the fingerprint and the operator's view are produced by the
    same function rather than by two that agree today. What a person reads when
    they approve is byte-for-byte the string the binding was taken over; a
    second encoder, however carefully written, is a place for them to drift.
    """
    try:
        return json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return None


def fingerprint(
    *,
    tenant: str | None,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, Any],
) -> str | None:
    """What makes two calls *the same call* for approval, or ``None``.

    ``None`` when the arguments will not encode — a value carrying something
    JSON cannot represent. **Refusing is the only correct answer**, and it means
    something stronger here than it does for the cache: the cache skips storing
    and the call proceeds, while a call that cannot be fingerprinted must be
    *refused outright*, because an approval that cannot be bound to it would be
    an approval for anything. A fallback encoding — `repr()`, `str()` — can map
    two different argument sets onto one string, and here that is not a collision
    between cache entries but a human's yes applied to a call they never saw.

    Arguments are canonicalised (keys sorted, no insignificant whitespace) so
    that two spellings of one call agree. Both identities are included for the
    reason ADR 0015 gives: an approval granted for an agent acting for alice must
    not be spendable by an agent acting for bob.
    """
    encoded = canonical(arguments)
    if encoded is None:
        return None

    material = json.dumps(
        [FINGERPRINT_VERSION, tenant, subject, actor, tool, encoded],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def new_token() -> str:
    """An opaque, unguessable `request_state`."""
    return secrets.token_urlsafe(TOKEN_BYTES)


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """One call, held, and what it is bound to.

    Frozen: a state change produces a new record rather than mutating one, so a
    store cannot hand out a reference somebody else can change underneath it.
    """

    token: str
    fingerprint: str
    subject: str
    tool: str
    rule: str | None
    """The policy rule that asked for a human. What an operator is shown, and
    what makes the request explainable — an approval nobody can attribute to a
    rule is a question nobody can answer."""

    created_at: float
    expires_at: float
    state: State = State.PENDING

    reason: str = ""
    """Free text from the operator who decided it, for the audit log. Never sent
    to the caller: a denial that explains itself is an oracle, the same argument
    `PolicyDeniedError` makes."""

    arguments_json: str | None = None
    """The canonical arguments, exactly as fingerprinted — or ``None`` when they
    exceeded `MAX_DISPLAYED_ARGUMENT_BYTES`.

    **An approval you cannot read is not an approval.** ADR 0045 keeps argument
    *values* out of the decision log because that log is widely readable; this
    record is not that. It lives in memory for five minutes and is read by
    exactly the person being asked to make a security decision about this
    specific call, and asking them to answer without seeing it is asking for a
    rubber stamp. Different reader, different threat model, opposite answer —
    stated here because it looks like an inconsistency and is not one.

    A string rather than a mapping so the record stays hashable, immutable, and
    identical to the fingerprint's input. The operator side parses it back.
    """

    arguments_bytes: int = 0

    tenant: str | None = None
    """Shown to the operator (task 58). "alice wants to delete the dataset" and
    "acme's alice wants to delete the dataset" are different sentences, and the
    person deciding is entitled to the one that is true. Defaulted so the
    single-tenant gateway constructs records exactly as before."""
    """Size of the canonical form, recorded even when it is withheld — so a
    withheld call reports *how* large rather than merely that it was too big."""

    def expired(self, now: float) -> bool:
        return now >= self.expires_at

    def decided(self, *, approved: bool, reason: str = "") -> ApprovalRequest:
        return replace(self, state=State.APPROVED if approved else State.DENIED, reason=reason)

    def consumed(self) -> ApprovalRequest:
        return replace(self, state=State.CONSUMED)


def request_for(
    *,
    tenant: str | None,
    subject: str,
    actor: str | None,
    tool: str,
    arguments: Mapping[str, Any],
    rule: str | None,
    now: float,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> ApprovalRequest | None:
    """A pending request for this call, or ``None`` if it cannot be bound to one.

    ``now`` is injected, never read from a clock in here, for the same reason the
    rate limiter takes it: the whole module is then a pure function of its
    inputs and expiry is tested by advancing a number rather than by sleeping.
    """
    encoded = canonical(arguments)
    if encoded is None:
        return None
    digest = fingerprint(
        tenant=tenant, subject=subject, actor=actor, tool=tool, arguments=arguments
    )
    if digest is None:  # pragma: no cover — `canonical` already proved it encodes
        return None
    size = len(encoded.encode("utf-8"))
    return ApprovalRequest(
        token=new_token(),
        fingerprint=digest,
        subject=subject,
        tenant=tenant,
        tool=tool,
        rule=rule,
        created_at=now,
        expires_at=now + ttl,
        arguments_json=encoded if size <= MAX_DISPLAYED_ARGUMENT_BYTES else None,
        arguments_bytes=size,
    )
