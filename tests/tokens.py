"""Real signing keys and well-formed claim sets, shared across the suite.

Not a conftest, because both the unit tests for validation and the integration
tests for the middleware need these and a conftest is only visible below its own
directory. The *fixtures* live in ``tests/conftest.py``; the machinery lives
here, so either can be imported without dragging in the other.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.test/realms/acp"
AUDIENCE = "agent-control-plane"
KID = "test-key-1"


class Keypair:
    """One signing key, plus the JWKS document that publishes its public half."""

    def __init__(self, kid: str = KID) -> None:
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = self.private.public_key()

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.public, as_dict=True)
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def sign(self, claims: dict[str, Any], *, alg: str = "RS256", kid: str | None = KID) -> str:
        headers = {"kid": kid} if kid else {}
        return jwt.encode(claims, self.private, algorithm=alg, headers=headers)


def claims(**overrides: Any) -> dict[str, Any]:
    """A well-formed access token's claims, before any tampering.

    ``act`` is present by default because delegation is the normal case for this
    gateway, not the exception: an agent acting for a user is the entire
    scenario the project exists to handle.
    """
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": "alice@example.test",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "client_id": "agent-fleet",
        "scope": "tools:read tools:call",
        "act": {"sub": "agent-7"},
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}
