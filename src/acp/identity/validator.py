"""Deciding whether a bearer token means anything, and whose it is.

Four checks, and each one is here because skipping it is a documented way to be
compromised rather than because a specification lists it.

**The algorithm is chosen by us, never read from the token.** A JWT's header
names its own algorithm, and a verifier that believes it can be told ``none``.
The subtler version is worse: when the key material is an RSA *public* key
fetched from a JWKS, an attacker can sign a token with ``HS256`` using that
public key — which is published — as the HMAC secret, and a verifier that
honours the header will happily check an HMAC with it and accept. That is why
the allow-list is asymmetric-only and why a symmetric algorithm in the
configuration is refused at construction rather than at verification: a
misconfiguration that can only fail closed is not a misconfiguration.

**The audience is checked.** A token is minted for a particular resource. One
issued for the expense system is a perfectly valid, correctly signed,
unexpired token — and accepting it here would let anything that can obtain a
token for *any* service in the estate act through this gateway. This is the
same problem RFC 8707 resource indicators solve on the outbound side in task 26.

**Expiry is required, not merely honoured.** ``exp`` is technically optional in
JWT. A token without it never expires, and a verifier that treats a missing
claim as "no constraint" turns one leaked token into permanent access.

**The issuer chooses the rules, before any rule is applied.** With more than
one trusted authorization server, "verify against whichever key matches, then
read ``iss``" accepts a token genuinely signed by server B while applying server
A's registration to it. So ``iss`` is read *first*, from the unverified payload,
and selects one registration — and the signature is then checked against that
registration's keys and that registration's issuer. A token that lies about who
issued it selects a registration whose keys will not verify it. See
``acp.identity.issuers``.

**The caller is told nothing about why.** Expired, wrong audience, bad
signature and unknown key all come back as one answer. A validator that
distinguishes them is an oracle an attacker can query, and the reason is
recorded in the log where the operator — who is not the attacker — can read it.
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
"""Asymmetric signatures only. See the module docstring for why a symmetric
algorithm alongside a public key is an accepted-forgery, not a configuration
preference."""

SYMMETRIC_PREFIXES: tuple[str, ...] = ("HS", "none")

DEFAULT_LEEWAY = 60.0
"""Clock skew tolerated on ``exp``, ``nbf`` and ``iat``.

A minute. Enough for hosts whose clocks disagree slightly, small enough that it
does not meaningfully extend the life of a token somebody wants revoked.
"""

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
            # Refused here rather than ignored later, because the failure mode
            # is silent acceptance of forged tokens rather than a rejected
            # request somebody would notice.
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
        """Verify ``token`` and build its principal, or raise.

        Every failure raises the same exception with the same message. The
        specific cause is logged, never returned.
        """
        header = self._header(token)
        self._reject_forbidden_algorithm(header.get("alg"))

        # Read who the token *claims* issued it, and let that choose the rules.
        # Nothing has been verified at this point; the safety comes from the two
        # steps below, which check the signature against this registration's
        # keys and `iss` against this registration's issuer. A lie here selects
        # a registration that cannot verify the token.
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
                # Written as a literal rather than assembled elsewhere so that
                # every verification this gateway performs is visible in one
                # place. `require` is the load-bearing entry: without it a token
                # missing `exp` is not rejected, it is simply never checked for
                # expiry, and one leaked token becomes permanent access.
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

        try:
            principal = from_claims(claims)
        except ValueError as exc:
            # Signed, unexpired, correctly addressed — and it does not say who
            # it is for. A token like that is not usable as an identity, and
            # accepting it would mean a request executing under no principal at
            # all while every log line claimed otherwise.
            raise _rejected("UnusableClaims") from exc

        # The tenant comes from the REGISTRATION, after verification — never
        # from a claim (task 58). The registration was selected by `iss` and
        # then proven: the signature verified against ITS keys and `iss`
        # matched ITS issuer. A token cannot reach this line under a
        # registration that did not issue it, so the tenant stamped here
        # inherits the mix-up defence rather than adding a new thing to trust.
        if registration.tenant is not None:
            principal = replace(principal, tenant=registration.tenant)
        return principal

    # -- internals ---------------------------------------------------------

    def _claimed_issuer(self, token: str) -> str | None:
        """The ``iss`` the token asserts, with nothing verified.

        Every check is switched off deliberately: this is not a validation, it
        is a lookup key, and running expiry or audience checks against a
        registration that has not been chosen yet would apply the wrong rules
        in order to decide which rules apply.
        """
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
        """Read the header's ``alg`` only in order to refuse it.

        ``jwt.decode`` already refuses anything outside the allow-list, so this
        is redundant — deliberately. It fails earlier, before a key lookup that
        a flood of ``none``-algorithm tokens would otherwise turn into work, and
        it makes the rejection explicit at the place a reader looks for it.
        """
        if isinstance(alg, str) and alg.startswith(SYMMETRIC_PREFIXES):
            raise _rejected("ForbiddenAlgorithm")


def _rejected(reason: str) -> AuthenticationError:
    """One message for every cause.

    The reason travels in ``details`` for the log and is stripped before the
    response is written — see ``acp.identity.asgi``. Telling a caller which of
    "expired", "wrong audience" and "bad signature" applied hands them a way to
    probe the configuration one request at a time.
    """
    logger.warning("auth.rejected", extra={"reason": reason})
    return AuthenticationError("the presented token is not valid", details={"reason": reason})


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
