"""Unit tests for issuer registration and cross-issuer isolation.

The test this file exists for is `test_a_token_signed_by_one_issuer_cannot_claim
_another`. Everything else is scaffolding around it.

With one trusted authorization server there is nothing to cross and none of this
matters. With two, the natural implementation — collect every trusted key,
verify against whichever matches, *then* read `iss` — accepts a token genuinely
signed by server B while applying server A's registration to it. B can mint A's
principals. These tests assert that cannot happen, and one of them asserts it in
the specific way that would catch the natural implementation.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import AuthenticationError, ConfigurationError
from acp.identity.issuers import (
    IssuerRegistration,
    IssuerRegistry,
    registry_from_documents,
    single_issuer,
)
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator

from ...tokens import Keypair

CORP = "https://idp.corp.test/realms/acp"
PARTNER = "https://idp.partner.test/"
AUDIENCE = "agent-control-plane"
PARTNER_AUDIENCE = "agent-control-plane-partner"


def registration(
    issuer: str, keypair: Keypair, audience: str = AUDIENCE, **policy: Any
) -> IssuerRegistration:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    return IssuerRegistration(
        policy=TokenPolicy(issuer=issuer, audience=audience, **policy),
        keys=JwksCache(
            f"{issuer}/keys",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ),
    )


def claims_for(issuer: str, audience: str = AUDIENCE, **overrides: Any) -> dict[str, Any]:
    import time  # noqa: PLC0415

    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": "alice",
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 300,
    }
    payload.update(overrides)
    return payload


def run(fn: Any) -> Any:
    return anyio.run(fn)


# ---------------------------------------------------------------------------
# The attack
# ---------------------------------------------------------------------------


def test_a_token_signed_by_one_issuer_cannot_claim_another(
    keypair: Keypair, other_keypair: Keypair
) -> None:
    """The authorization-server mix-up, in its resource-server form.

    The partner holds a real signing key and this gateway really trusts it —
    for tokens claiming to be from the partner. Here the partner signs a token
    claiming `iss` of the corporate directory. A gateway that verified against
    any trusted key and read `iss` afterwards would accept it, and the partner
    would be able to mint corporate principals at will.

    Selection by `iss` makes it impossible: claiming the corporate issuer
    selects the corporate registration, whose keys do not verify this signature.
    """
    registry = IssuerRegistry(
        [registration(CORP, keypair), registration(PARTNER, other_keypair, PARTNER_AUDIENCE)]
    )
    validator = TokenValidator(issuers=registry)

    forged = other_keypair.sign(claims_for(CORP), kid=other_keypair.kid)

    with pytest.raises(AuthenticationError):
        run(lambda: validator.validate(forged))


def test_each_issuer_keeps_its_own_audience(keypair: Keypair, other_keypair: Keypair) -> None:
    """The second half of "cannot be crossed". The partner's own token, signed
    with the partner's key and honestly claiming the partner's issuer, still
    carries the partner's audience — and must not be usable as though it
    carried the corporate one."""
    registry = IssuerRegistry(
        [registration(CORP, keypair), registration(PARTNER, other_keypair, PARTNER_AUDIENCE)]
    )
    validator = TokenValidator(issuers=registry)

    # Honest issuer, honest key, but addressed to the corporate audience.
    crossed = other_keypair.sign(claims_for(PARTNER, audience=AUDIENCE), kid=other_keypair.kid)

    with pytest.raises(AuthenticationError):
        run(lambda: validator.validate(crossed))


def test_each_issuer_is_verified_against_only_its_own_keys(
    keypair: Keypair, other_keypair: Keypair
) -> None:
    """Both honest tokens work, which is what makes the two rejections above
    mean something rather than being a validator that refuses everything."""
    registry = IssuerRegistry(
        [registration(CORP, keypair), registration(PARTNER, other_keypair, PARTNER_AUDIENCE)]
    )
    validator = TokenValidator(issuers=registry)

    corporate = keypair.sign(claims_for(CORP), kid=keypair.kid)
    partner = other_keypair.sign(
        claims_for(PARTNER, audience=PARTNER_AUDIENCE), kid=other_keypair.kid
    )

    assert run(lambda: validator.validate(corporate)).issuer == CORP
    assert run(lambda: validator.validate(partner)).issuer == PARTNER


def test_an_unregistered_issuer_is_refused(keypair: Keypair) -> None:
    registry = single_issuer(
        TokenPolicy(issuer=CORP, audience=AUDIENCE), registration(CORP, keypair).keys
    )
    validator = TokenValidator(issuers=registry)

    stranger = keypair.sign(claims_for("https://idp.nobody.test/"), kid=keypair.kid)

    with pytest.raises(AuthenticationError):
        run(lambda: validator.validate(stranger))


def test_a_token_with_no_issuer_at_all_is_refused(keypair: Keypair) -> None:
    """There is nothing to select on. Falling back to "the only registration"
    would work today and become a cross-issuer hole the day a second server is
    registered — silently, in a file nobody was editing."""
    registry = single_issuer(
        TokenPolicy(issuer=CORP, audience=AUDIENCE), registration(CORP, keypair).keys
    )
    validator = TokenValidator(issuers=registry)

    anonymous = keypair.sign({"sub": "alice", "aud": AUDIENCE, "exp": 9999999999}, kid=keypair.kid)

    with pytest.raises(AuthenticationError):
        run(lambda: validator.validate(anonymous))


def test_the_rejection_does_not_reveal_which_issuers_are_trusted(keypair: Keypair) -> None:
    """Which authorization servers an organisation trusts is a map for somebody
    deciding where to attack, and an unauthenticated caller can ask this
    question as often as they like."""
    registry = IssuerRegistry([registration(CORP, keypair)])

    with pytest.raises(AuthenticationError) as caught:
        registry.registration_for("https://idp.nobody.test/")

    assert CORP not in str(caught.value.to_jsonrpc_error())


# ---------------------------------------------------------------------------
# The registry itself
# ---------------------------------------------------------------------------


def test_an_issuer_registered_twice_is_refused(keypair: Keypair) -> None:
    """The second would silently win, and which one that is depends on file
    ordering. When the thing being chosen is "which audience must a token
    carry", ambiguity is not a tie to be broken."""
    with pytest.raises(ConfigurationError, match="more than once"):
        IssuerRegistry([registration(CORP, keypair), registration(CORP, keypair, "other")])


def test_an_empty_registry_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="at least one"):
        IssuerRegistry([])


def test_issuers_are_matched_by_exact_string(keypair: Keypair) -> None:
    """RFC 8414 §2 compares issuers as strings. Trimming a trailing slash here
    would mean this gateway's idea of "the same authorization server" differed
    from the token's, which is the disagreement the whole module is about."""
    registry = IssuerRegistry([registration(CORP, keypair)])

    assert registry.registration_for(CORP).issuer == CORP
    with pytest.raises(AuthenticationError):
        registry.registration_for(CORP + "/")


def test_the_registry_reports_what_it_holds(keypair: Keypair, other_keypair: Keypair) -> None:
    registry = IssuerRegistry(
        [registration(PARTNER, other_keypair, PARTNER_AUDIENCE), registration(CORP, keypair)]
    )

    assert len(registry) == 2
    assert registry.issuers == sorted([CORP, PARTNER])


# ---------------------------------------------------------------------------
# Building registrations from configuration
# ---------------------------------------------------------------------------


def test_documents_become_registrations() -> None:
    registrations = registry_from_documents(
        [
            {"issuer": CORP, "audience": AUDIENCE, "jwks_url": f"{CORP}/keys"},
            {
                "issuer": PARTNER,
                "audience": PARTNER_AUDIENCE,
                "jwks_url": f"{PARTNER}keys",
                "algorithms": ["ES256"],
            },
        ],
        default_algorithms=["RS256"],
        leeway=30.0,
    )

    assert [r.issuer for r in registrations] == [CORP, PARTNER]
    assert registrations[0].policy.algorithms == ("RS256",)
    assert registrations[1].policy.algorithms == ("ES256",), "per-issuer override ignored"
    assert registrations[0].policy.leeway == 30.0


@pytest.mark.parametrize("field", ["issuer", "audience", "jwks_url"])
def test_a_registration_missing_a_required_field_is_refused(field: str) -> None:
    document = {"issuer": CORP, "audience": AUDIENCE, "jwks_url": f"{CORP}/keys"}
    del document[field]

    with pytest.raises(ConfigurationError, match=field):
        registry_from_documents([document], default_algorithms=["RS256"], leeway=60.0)


def test_a_symmetric_algorithm_for_one_issuer_is_still_refused() -> None:
    """Per-issuer overrides do not get their own, weaker rules. A JWKS publishes
    public keys whichever server serves it."""
    with pytest.raises(ConfigurationError, match="symmetric"):
        registry_from_documents(
            [
                {
                    "issuer": CORP,
                    "audience": AUDIENCE,
                    "jwks_url": f"{CORP}/keys",
                    "algorithms": ["HS256"],
                }
            ],
            default_algorithms=["RS256"],
            leeway=60.0,
        )
