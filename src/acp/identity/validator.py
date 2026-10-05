"""Bearer token validation: resolve a token to a principal, or reject it.

Algorithms come from an asymmetric-only allow-list, never the header (blocks ``none`` and
HS256-with-public-key). Audience and issuer are bound to the registration selected by
the token's ``iss`` before verification (see ``acp.identity.issuers``). ``exp`` is
required. Every rejection gives the caller the same answer; the cause goes to the log.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

import jwt

from acp.exceptions import AuthenticationError, ConfigurationError
from acp.identity.principal import Principal, from_claims

if TYPE_CHECKING:  # pragma: no cover - import cycle: issuers imports TokenPolicy
    from acp.identity.issuers import IssuerRegistry

logger = logging.getLogger(__name__)

DEFAULT_ALGORITHMS: tuple[str, ...] = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")
"""Asymmetric signatures only; see the module docstring."""

SYMMETRIC_PREFIXES: tuple[str, ...] = ("HS", "none")

DEFAULT_LEEWAY = 60.0
"""Clock skew tolerated on ``exp``, ``nbf`` and ``iat``, in seconds."""

REQUIRED_CLAIMS: tuple[str, ...] = ("sub", "iss", "aud", "exp", "iat")


@dataclass(frozen=True, slots=True)
class TokenPolicy:
    """What this gateway will accept as proof of identity."""

    issuer: str
    audience: str
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    leeway: float = DEFAULT_LEEWAY
    required_claims: tuple[str, ...] = REQUIRED_CLAIMS

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience:
            msg = "token validation needs both an issuer and an audience"
            raise ConfigurationError(msg)
        bad = [a for a in self.algorithms if a.startswith(SYMMETRIC_PREFIXES)]
        if bad:
            # Refused at construction: the failure mode is silently accepting forgeries.
            msg = (
                f"symmetric or unsigned algorithms are not permitted: {', '.join(bad)}. "
                f"A JWKS publishes public keys, and an attacker can sign HS256 with one."
            )
            raise ConfigurationError(msg)
        if not self.algorithms:
            msg = "at least one signature algorithm must be permitted"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class TokenValidator:
    """Verifies a bearer token and returns the principal it names."""

    issuers: IssuerRegistry

    async def validate(self, token: str) -> Principal:
        """Verify ``token`` and build its principal.

        Raises:
            AuthenticationError: On every failure, with one message; the cause is logged.
        """
        header = self._header(token)
        self._reject_forbidden_algorithm(header.get("alg"))

        # Unverified `iss` selects the rules; a lie selects keys that cannot verify it.
        registration = self.issuers.registration_for(self._claimed_issuer(token))
        policy = registration.policy
        key = await registration.keys.key_for(_optional_str(header.get("kid")))

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=list(policy.algorithms),
                audience=policy.audience,
                issuer=policy.issuer,
                leeway=policy.leeway,
                # All checks in one literal. `require` is load-bearing: without it a token
                # missing `exp` is never checked for expiry.
                options={
                    "require": list(policy.required_claims),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise _rejected(type(exc).__name__) from exc
        except (TypeError, ValueError) as exc:
            # Mixed EC/RSA key sets can make PyJWT raise TypeError; reject it like any other
            # failure rather than surface a 500.
            raise _rejected(type(exc).__name__) from exc

        try:
            principal = from_claims(claims)
        except ValueError as exc:
            # A valid token that names no subject is not an identity.
            raise _rejected("UnusableClaims") from exc

        # Tenant comes from the verified registration, never a claim.
        if registration.tenant is not None:
            principal = replace(principal, tenant=registration.tenant)
        return principal

    # -- internals ---------------------------------------------------------

    def _claimed_issuer(self, token: str) -> str | None:
        """Return the token's asserted ``iss``, unverified; it is only a lookup key."""
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise _rejected("MalformedPayload") from exc
        return _optional_str(payload.get("iss"))

    def _header(self, token: str) -> dict[str, Any]:
        try:
            header: dict[str, Any] = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise _rejected("MalformedHeader") from exc
        return header

    def _reject_forbidden_algorithm(self, alg: Any) -> None:
        """Refuse a symmetric or ``none`` ``alg`` early, before any key lookup.

        Redundant with ``jwt.decode`` on purpose: it stops a flood of such tokens cheaply.
        """
        if isinstance(alg, str) and alg.startswith(SYMMETRIC_PREFIXES):
            raise _rejected("ForbiddenAlgorithm")


def _rejected(reason: str) -> AuthenticationError:
    """Return the single rejection error; the reason goes in ``details`` for the log only.

    ``acp.identity.asgi`` strips it before responding, so callers cannot probe the config.
    """
    logger.warning("auth.rejected", extra={"reason": reason})
    return AuthenticationError("the presented token is not valid", details={"reason": reason})


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
