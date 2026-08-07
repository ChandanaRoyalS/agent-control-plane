"""Fixtures shared by the whole suite.

Every token in the identity tests is genuinely signed with a genuinely generated
key pair and verified through the same PyJWT call the gateway makes. That costs
about a second of test time and buys the only thing worth having: a suite that
would actually notice if signature verification stopped happening.

Stubbing the decode step instead would exercise the code *around* the security
control while leaving the control itself untested — which this project has
already learned the price of once (ADR 0008).
"""

from __future__ import annotations

import pytest

from .tokens import Keypair


@pytest.fixture(scope="session")
def keypair() -> Keypair:
    """Session-scoped: RSA generation is the slowest thing in this suite, and
    one key is enough for every test that is not specifically about rotation."""
    return Keypair()


@pytest.fixture(scope="session")
def other_keypair() -> Keypair:
    """A second, unrelated key — for "signed by somebody else entirely"."""
    return Keypair(kid="attacker-key")
