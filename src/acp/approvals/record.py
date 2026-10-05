"""What a pending approval is, and what it is bound to (ADR 0048).

An approval is granted to a call, not a token: each request records a fingerprint
of who asked, which tool and which arguments, and the retry must match it, so an
approved token cannot be replayed with different arguments. Kept separate from the
result cache key (ADR 0035), which fails in the opposite direction.
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
"""Stamped into every fingerprint; v2 added the tenant so approvals cannot cross tenants."""

TOKEN_BYTES: Final = 32
"""256 bits from `secrets`, never derived from the call, so it cannot be guessed."""

DEFAULT_TTL_SECONDS: Final = 300.0
"""Seconds a request waits before it is refused.

Expiry is the default-deny, checked when the token is resolved rather than by a
sweeper.
"""

MAX_DISPLAYED_ARGUMENT_BYTES: Final = 8192
"""Largest canonical arguments shown to an operator.

Beyond it the arguments are withheld entirely, never truncated, so the operator
never sees a different call from the one fingerprinted.
"""


class State(StrEnum):
    """Where a request has got to.

    No `EXPIRED` member: expiry is computed from the clock, so it holds even if
    nothing ran on time.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    """Spent; an approval is good for one call."""


def canonical(arguments: Mapping[str, Any]) -> str | None:
    """The one encoding of ``arguments`` that everything else agrees on.

    Sorted keys, no whitespace. ``None`` when JSON cannot represent the value;
    the caller must refuse, never fall back to `repr()`. Both the fingerprint and
    the operator's view use it, so the person approves the exact bound string.
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

    ``None`` when the arguments will not encode; the call must then be refused
    outright, since an unbound approval would approve anything. Subject and actor
    are both included (ADR 0015).
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

    Frozen: a state change produces a new record.
    """

    token: str
    fingerprint: str
    subject: str
    tool: str
    rule: str | None
    """The policy rule that asked for a human, shown to the operator."""

    created_at: float
    expires_at: float
    state: State = State.PENDING

    reason: str = ""
    """Operator's free text, for the audit log; never sent to the caller (no oracle)."""

    arguments_json: str | None = None
    """The canonical arguments as fingerprinted, or ``None`` past the display limit.

    Shown to the operator, unlike the decision log (ADR 0045): a different reader
    who must see the call to judge it. A string so the record stays hashable.
    """

    arguments_bytes: int = 0
    """Size of the canonical form, recorded even when withheld."""

    tenant: str | None = None
    """Shown to the operator; ``None`` for a single-tenant gateway."""

    actor: str | None = None
    """The agent acting for ``subject`` (RFC 8693 ``act``, ADR 0015); shown and audited."""

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

    ``now`` is injected, keeping this module free of clocks.
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
        actor=actor,
        tool=tool,
        rule=rule,
        created_at=now,
        expires_at=now + ttl,
        arguments_json=encoded if size <= MAX_DISPLAYED_ARGUMENT_BYTES else None,
        arguments_bytes=size,
    )
