"""Unit tests for token validation.

Every token here is really signed and really verified. The tests that matter are
the ones asserting a *rejection*, because a validator that accepts everything
passes every happy-path test ever written for it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any

import anyio
import jwt
import pytest

from acp.exceptions import AuthenticationError, ConfigurationError
from acp.identity.validator import TokenPolicy, TokenValidator

from ...tokens import AUDIENCE, ISSUER, Keypair, claims


class StubKeys:
    """Stands in for the JWKS cache. The cache has its own tests next door;
    here the point is the verification, not the fetching."""

    def __init__(self, keypair: Keypair) -> None:
        self._keypair = keypair
        self.lookups: list[str | None] = []

    async def key_for(self, kid: str | None) -> Any:
        self.lookups.append(kid)
        return self._keypair.public


def validator(keypair: Keypair, **policy: Any) -> TokenValidator:
    settings = {"issuer": ISSUER, "audience": AUDIENCE, **policy}
    keys: Any = StubKeys(keypair)
    return TokenValidator(policy=TokenPolicy(**settings), keys=keys)


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# The happy path, so the rejections mean something
# ---------------------------------------------------------------------------


def test_a_valid_token_resolves_to_a_principal(keypair: Keypair) -> None:
    token = keypair.sign(claims())

    principal = run(lambda: validator(keypair).validate(token))

    assert principal.subject == "alice@example.test"
    assert principal.actor is not None
    assert principal.actor.subject == "agent-7"
    assert principal.client_id == "agent-fleet"
    assert principal.scopes == {"tools:read", "tools:call"}


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


def test_a_token_signed_by_somebody_else_is_refused(
    keypair: Keypair, other_keypair: Keypair
) -> None:
    """The base case. Everything else in this file is a way of getting here
    without possessing the key."""
    forged = other_keypair.sign(claims())

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(forged))


def test_a_tampered_payload_is_refused(keypair: Keypair) -> None:
    """Flipping a character in the payload segment invalidates the signature —
    which is the entire security property, and worth one test that says so
    rather than trusting it."""
    header, payload, signature = keypair.sign(claims()).split(".")
    mutated = payload[:-4] + ("A" if payload[-4] != "A" else "B") + payload[-3:]

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(f"{header}.{mutated}.{signature}"))


def test_an_unsigned_token_is_refused(keypair: Keypair) -> None:
    """`alg: none` is the oldest JWT attack there is: strip the signature,
    announce that none was used, and hope the verifier believes the header."""
    unsigned = jwt.encode(claims(), key="", algorithm="none")

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(unsigned))


def test_a_public_key_cannot_be_used_as_an_hmac_secret(keypair: Keypair) -> None:
    """The algorithm-confusion attack, and the reason the allow-list is
    asymmetric-only.

    A JWKS publishes *public* keys. An attacker takes the published RSA public
    key, signs a token of their own choosing with HS256 using that key's PEM as
    the HMAC secret, and a verifier that honours the token's own `alg` header
    computes an HMAC with the same public value and accepts. The forged token is
    valid, and the attacker needed nothing that was not already published.
    """
    forged = forge_hs256(keypair, claims())

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(forged))


def forge_hs256(keypair: Keypair, payload: dict[str, Any]) -> str:
    """Assemble the algorithm-confusion token by hand.

    PyJWT refuses to *encode* HS256 with a PEM key — a guard on the signing side
    that an attacker simply does not use. Reproducing the attack therefore means
    building the token the way an attacker would, from base64url segments and an
    HMAC, rather than politely asking a library that has already decided not to
    help. A test that used the library's `encode` here would be asserting that
    PyJWT protects us, when the property under test is that *we* do.
    """
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    public_pem = keypair.public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def segment(data: dict[str, Any]) -> bytes:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=")

    signing_input = (
        segment({"alg": "HS256", "typ": "JWT", "kid": keypair.kid}) + b"." + segment(payload)
    )
    signature = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def test_a_symmetric_algorithm_cannot_even_be_configured() -> None:
    """Refused at construction, not at verification.

    A misconfiguration that can only fail closed is not really a
    misconfiguration. This one fails *open* — it accepts forged tokens — so it
    has to be impossible to express rather than merely unlikely to be written.
    """
    with pytest.raises(ConfigurationError, match="symmetric"):
        TokenPolicy(issuer=ISSUER, audience=AUDIENCE, algorithms=("RS256", "HS256"))

    with pytest.raises(ConfigurationError, match="symmetric"):
        TokenPolicy(issuer=ISSUER, audience=AUDIENCE, algorithms=("none",))


# ---------------------------------------------------------------------------
# Addressing: who the token was for
# ---------------------------------------------------------------------------


def test_a_token_for_another_service_is_refused(keypair: Keypair) -> None:
    """Correctly signed by the right issuer, unexpired, and minted for the
    expense system. Accepting it would let anything that can obtain a token for
    *any* service in the estate act through this gateway — the same problem
    RFC 8707 resource indicators solve on the way out in task 26."""
    token = keypair.sign(claims(aud="expenses-api"))

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(token))


def test_a_token_from_another_issuer_is_refused(keypair: Keypair) -> None:
    """Possession of a signing key that this gateway happens to trust is not
    the same as being the authorization server it was told to trust. Task 23
    hardens this further with RFC 9207."""
    token = keypair.sign(claims(iss="https://idp.attacker.test/"))

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(token))


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def test_an_expired_token_is_refused(keypair: Keypair) -> None:
    now = int(time.time())
    token = keypair.sign(claims(iat=now - 3600, exp=now - 1800))

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(token))


def test_a_token_with_no_expiry_is_refused(keypair: Keypair) -> None:
    """`exp` is optional in JWT. A token without it never expires, and a
    verifier that treats a missing claim as "no constraint" turns one leaked
    token into permanent access."""
    token = keypair.sign(claims(exp=None))

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(token))


def test_a_token_not_yet_valid_is_refused(keypair: Keypair) -> None:
    now = int(time.time())
    token = keypair.sign(claims(nbf=now + 3600, exp=now + 7200))

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(token))


def test_small_clock_skew_is_tolerated(keypair: Keypair) -> None:
    """Hosts disagree slightly and always have. A minute of leeway is not
    meaningful extra life for a token somebody wants revoked, and without it a
    correctly issued token fails for a reason nobody can debug from the
    outside."""
    now = int(time.time())
    token = keypair.sign(claims(iat=now - 200, exp=now - 5))

    principal = run(lambda: validator(keypair, leeway=60.0).validate(token))

    assert principal.subject == "alice@example.test"


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_a_token_that_names_nobody_is_refused(keypair: Keypair) -> None:
    """Verified, addressed to us, unexpired — and no `sub`. Required by the
    policy, so PyJWT rejects it before the claim reader ever runs."""
    token = keypair.sign(claims(sub=None))

    with pytest.raises(AuthenticationError):
        run(lambda: validator(keypair).validate(token))


def test_garbage_is_refused_without_raising_something_else(keypair: Keypair) -> None:
    """A malformed header must come back as an authentication failure rather
    than as whatever the JWT library felt like raising — the middleware catches
    one type, and anything else becomes a 500 on an unauthenticated path."""
    for junk in ("", "not-a-jwt", "a.b.c", "..", "eyJhbGciOiJSUzI1NiJ9"):
        with pytest.raises(AuthenticationError):
            run(lambda token=junk: validator(keypair).validate(token))


def test_the_kid_from_the_header_is_what_gets_looked_up(keypair: Keypair) -> None:
    keys = StubKeys(keypair)
    v = TokenValidator(policy=TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys=keys)  # type: ignore[arg-type]

    run(lambda: v.validate(keypair.sign(claims())))

    assert keys.lookups == [keypair.kid]


# ---------------------------------------------------------------------------
# What the caller is told, and what only the operator sees
# ---------------------------------------------------------------------------


def test_every_rejection_gives_the_caller_the_same_message(keypair: Keypair) -> None:
    """A validator that distinguishes "expired" from "wrong audience" from "bad
    signature" is an oracle an attacker can query one request at a time until
    they know the configuration."""
    now = int(time.time())
    tokens = [
        keypair.sign(claims(aud="somewhere-else")),
        keypair.sign(claims(iat=now - 3600, exp=now - 1800)),
        keypair.sign(claims(iss="https://elsewhere.test")),
    ]

    messages = set()
    for token in tokens:
        with pytest.raises(AuthenticationError) as caught:
            run(lambda t=token: validator(keypair).validate(t))
        messages.add(caught.value.message)

    assert len(messages) == 1


def test_the_specific_reason_reaches_the_log(
    keypair: Keypair, caplog: pytest.LogCaptureFixture
) -> None:
    """The operator is not the attacker. Everything withheld from the response
    has to be somewhere the person debugging this can find it."""
    token = keypair.sign(claims(aud="somewhere-else"))

    with (
        caplog.at_level(logging.WARNING, logger="acp.identity.validator"),
        pytest.raises(AuthenticationError),
    ):
        run(lambda: validator(keypair).validate(token))

    rejected = [r for r in caplog.records if r.message == "auth.rejected"]
    assert rejected
    assert rejected[0].reason == "InvalidAudienceError"  # type: ignore[attr-defined]


def test_an_authentication_failure_is_recoverable(keypair: Keypair) -> None:
    """`recoverable` is forwarded to the agent and is the signal it reasons
    over. An expired token can be exchanged for a new one and the call retried,
    which is genuinely different from "this will never work" — though it is not
    an invitation to retry the *same* token."""
    with pytest.raises(AuthenticationError) as caught:
        run(lambda: validator(keypair).validate("nonsense"))

    assert caught.value.to_jsonrpc_error()["data"]["recoverable"] is True


def test_the_token_itself_never_appears_in_the_error(keypair: Keypair) -> None:
    """An error object travels into logs and, for other error types, back to the
    caller. A bearer token in either is a credential leak."""
    token = keypair.sign(claims(aud="somewhere-else"))

    with pytest.raises(AuthenticationError) as caught:
        run(lambda: validator(keypair).validate(token))

    rendered = str(caught.value.to_jsonrpc_error())
    assert token not in rendered
    assert token[:24] not in rendered
