"""The identity a request runs under: a subject (the human) and an actor (the workload).

The actor uses RFC 8693 §4.1's ``act`` claim so exchanged credentials stay readable by
other systems. Unauthenticated is ``None`` rather than an anonymous Principal, so
`mypy --strict` rejects code that forgets to check.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

SUBJECT_CLAIM = "sub"
ISSUER_CLAIM = "iss"
ACTOR_CLAIM = "act"
"""RFC 8693 §4.1. Nested: the immediate actor is the outermost ``act``."""

CLIENT_ID_CLAIM = "client_id"
"""RFC 9068 §2.2 — the OAuth client that obtained the token."""

SCOPE_CLAIM = "scope"

MAX_DELEGATION_DEPTH = 8
"""Maximum ``act`` nesting walked; the claim is attacker-supplied."""


@dataclass(frozen=True, slots=True)
class Actor:
    """A workload acting on someone's behalf."""

    subject: str
    issuer: str | None = None

    def __str__(self) -> str:
        return self.subject


@dataclass(frozen=True, slots=True)
class Principal:
    """The identity a request is executed under.

    Built only by :mod:`acp.identity.validator` from verified claims; nothing here
    re-checks.
    """

    subject: str
    issuer: str
    actor: Actor | None = None
    client_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    """OAuth scopes, logged only; policy does not consult them (W11 of the external review)."""

    tenant: str | None = None
    """Tenant, stamped from the verifying registration and never from a claim."""

    delegation_chain: tuple[str, ...] = ()
    """Every actor from the immediate one outward, for the log; policy uses the immediate."""

    @property
    def label(self) -> str:
        """Return ``subject`` or ``subject via actor``, for logs and errors."""
        return f"{self.subject} via {self.actor}" if self.actor else self.subject

    def as_log_fields(self) -> dict[str, Any]:
        """Return identifier-only log fields: no token, raw claims, email or name."""
        return {
            "principal": self.subject,
            "principal_issuer": self.issuer,
            "actor": self.actor.subject if self.actor else None,
            "delegation_chain": list(self.delegation_chain),
            "client_id": self.client_id,
            "scopes": sorted(self.scopes),
            "tenant": self.tenant,
        }


def from_claims(claims: Mapping[str, Any]) -> Principal:
    """Build a principal from verified claims (pure, no cryptography).

    Raises:
        ValueError: ``sub`` or ``iss`` is missing or empty.
    """
    subject = _require_str(claims, SUBJECT_CLAIM)
    issuer = _require_str(claims, ISSUER_CLAIM)
    actor, chain = _actor_chain(claims.get(ACTOR_CLAIM))

    return Principal(
        subject=subject,
        issuer=issuer,
        actor=actor,
        client_id=_optional_str(claims.get(CLIENT_ID_CLAIM)),
        scopes=_scopes(claims.get(SCOPE_CLAIM)),
        delegation_chain=chain,
    )


def _actor_chain(value: Any) -> tuple[Actor | None, tuple[str, ...]]:
    """Walk the nested ``act`` claim, immediate actor first, up to ``MAX_DELEGATION_DEPTH``."""
    chain: list[str] = []
    immediate: Actor | None = None
    current = value

    for _ in range(MAX_DELEGATION_DEPTH):
        if not isinstance(current, Mapping):
            break
        subject = _optional_str(current.get(SUBJECT_CLAIM))
        if subject is None:
            # End the chain rather than reject the token over malformed provenance.
            break
        if immediate is None:
            immediate = Actor(subject=subject, issuer=_optional_str(current.get(ISSUER_CLAIM)))
        chain.append(subject)
        current = current.get(ACTOR_CLAIM)

    return immediate, tuple(chain)


def _scopes(value: Any) -> frozenset[str]:
    """Parse a space-delimited scope string (RFC 6749 §3.3), also accepting a list."""
    if isinstance(value, str):
        return frozenset(value.split())
    if isinstance(value, list):
        return frozenset(str(item) for item in value)
    return frozenset()


def _require_str(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        msg = f"token claim {name!r} is missing or not a non-empty string"
        raise ValueError(msg)
    return value


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# ---------------------------------------------------------------------------
# The current request's principal
# ---------------------------------------------------------------------------

_principal: ContextVar[Principal | None] = ContextVar("acp_principal", default=None)
"""Request-scoped, like the request ID (see ``acp.observability.context``)."""


def bind_principal(principal: Principal | None) -> None:
    _principal.set(principal)


def current_principal() -> Principal | None:
    """Return the authenticated principal, or ``None`` if the request was not authenticated."""
    return _principal.get()


_subject_token: ContextVar[str | None] = ContextVar("acp_subject_token", default=None)
"""The raw inbound token, kept off ``Principal`` so identity never carries a credential.

Only ``acp.identity.exchange`` reads it, sending it to the issuing server's token endpoint
(RFC 8693) and nowhere else. Reading it from ``acp.upstream`` would be the bug.
"""


def bind_subject_token(token: str | None) -> None:
    _subject_token.set(token)


def current_subject_token() -> str | None:
    """The raw inbound token, for exchange only. See ``_subject_token``."""
    return _subject_token.get()
