"""Who an errand is actually for.

The problem this project exists to solve, stated precisely. An agent connected
to internal systems normally holds one service credential per system, carrying
the union of every permission any user might need — so a request made on behalf
of an intern reaches the same data as one made on behalf of the CFO. There is no
principal anywhere in that picture; there is only the agent.

A principal here is therefore **two identities, not one**. The *subject* is the
human the work is being done for. The *actor* is the workload doing it. Both are
needed and neither substitutes for the other: policy about what may be read is
about the subject, and policy about which agent may act at all — or which agent
has been compromised — is about the actor.

**The representation is not invented.** RFC 8693 §4.1 defines the ``act`` claim
for exactly this: a token whose ``sub`` is the user and whose ``act`` names the
party acting on their behalf, nestable into a chain when a request passes
through several. Using the standard claim rather than a bespoke one is what will
let the token exchange in task 25 produce credentials another system can read.

**Unauthenticated is ``None``, not a special Principal.** An "anonymous
principal" object is a thing that looks like a principal to every caller that
forgets to check, and forgetting to check is the entire failure mode. ``None``
makes `mypy --strict` refuse to compile the code that forgets — a guarantee no
amount of care provides, and free here because the project already runs strict.
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
EXPIRY_CLAIM = "exp"

MAX_DELEGATION_DEPTH = 8
"""How far down an ``act`` chain this will walk before giving up.

The claim nests arbitrarily and arrives from outside. A token carrying a chain
ten thousand deep is a small string that costs the gateway a lot of work, and a
recursive walk with no bound is a stack overflow with a JSON body.
"""


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

    Built only by :mod:`acp.identity.validator`, from claims that have already
    been cryptographically verified. Nothing here re-checks anything: a
    ``Principal`` that exists is one that was proven, and keeping the proving in
    one place is what stops a second, laxer path appearing later.
    """

    subject: str
    issuer: str
    actor: Actor | None = None
    client_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    expires_at: int | None = None
    delegation_chain: tuple[str, ...] = ()
    """Every actor from the immediate one outward, when the token carries a
    chain. Kept because "the CFO's token, via an agent, via a scheduler nobody
    authorized" is a sentence that should be answerable from an audit log."""

    @property
    def is_delegated(self) -> bool:
        return self.actor is not None

    @property
    def label(self) -> str:
        """A short human-readable identity, for logs and error messages.

        Deliberately shows both halves. "alice" and "alice via
        agent-7" describe different situations, and a log line that renders them
        identically is one that cannot answer the only question worth asking
        after an incident.
        """
        return f"{self.subject} via {self.actor}" if self.actor else self.subject

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def as_log_fields(self) -> dict[str, Any]:
        """Fields safe to attach to every log line for this request.

        Identifiers only. No token, no raw claims, and no email or name even if
        the identity provider supplied them — an audit trail needs to say *which
        principal*, not *who the person is*, and the two have very different
        retention rules attached.
        """
        return {
            "principal": self.subject,
            "principal_issuer": self.issuer,
            "actor": self.actor.subject if self.actor else None,
            "client_id": self.client_id,
        }


def from_claims(claims: Mapping[str, Any]) -> Principal:
    """Build a principal from verified claims.

    Pure, and deliberately separate from anything that touches cryptography:
    the interesting mistakes in this file are about *reading* a token correctly,
    and they are much easier to test when reading is not entangled with
    verifying.
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
        expires_at=_optional_int(claims.get(EXPIRY_CLAIM)),
        delegation_chain=chain,
    )


def _actor_chain(value: Any) -> tuple[Actor | None, tuple[str, ...]]:
    """Walk the nested ``act`` claim, immediate actor first.

    RFC 8693 nests: ``act.act`` is the party that delegated to ``act``. The
    immediate actor is the one that matters for authorization now; the rest is
    provenance. Bounded by ``MAX_DELEGATION_DEPTH`` because the claim is
    attacker-supplied and an unbounded walk over it is a denial of service
    written in JSON.
    """
    chain: list[str] = []
    immediate: Actor | None = None
    current = value

    for _ in range(MAX_DELEGATION_DEPTH):
        if not isinstance(current, Mapping):
            break
        subject = _optional_str(current.get(SUBJECT_CLAIM))
        if subject is None:
            # An `act` with no `sub` names nobody. Treated as the end of the
            # chain rather than as an error: the claim is optional, and
            # rejecting a whole token over a malformed provenance record would
            # make an identity provider's cosmetic bug an outage here.
            break
        if immediate is None:
            immediate = Actor(subject=subject, issuer=_optional_str(current.get(ISSUER_CLAIM)))
        chain.append(subject)
        current = current.get(ACTOR_CLAIM)

    return immediate, tuple(chain)


def _scopes(value: Any) -> frozenset[str]:
    """OAuth scope is a space-delimited string (RFC 6749 §3.3).

    Some providers send a list anyway. Both are accepted, because rejecting a
    list would be correct by the letter and would break against real identity
    providers for no security benefit.
    """
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


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# ---------------------------------------------------------------------------
# The current request's principal
# ---------------------------------------------------------------------------

_principal: ContextVar[Principal | None] = ContextVar("acp_principal", default=None)
"""Request-scoped, for the same reason the request ID is — see
``acp.observability.context``. A parameter threaded through every function
signature would reach the policy engine eventually, but only by putting an
identity argument on every interface between here and there."""


def bind_principal(principal: Principal | None) -> None:
    _principal.set(principal)


def current_principal() -> Principal | None:
    """The authenticated principal, or ``None``.

    ``None`` means *this request was not authenticated* — either because
    authentication is not configured, or because the request never reached a
    place that authenticates. Callers must handle it; the type says so.
    """
    return _principal.get()
