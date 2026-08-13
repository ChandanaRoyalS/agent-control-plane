"""Tenant labels on issuer registrations — task 58's root of trust.

The tenant is a property of the *registration*, never of a claim. Most of
these are configuration tests — what a label may be, and that the same
validation guards both paths that read it — and the last two are the ones
that matter: a validator with two registrations stamps each verified token
with its own issuer's tenant, and a token *claiming* a tenant gets the
registration's answer, not its own.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import ConfigurationError
from acp.identity.issuers import (
    IssuerRegistration,
    IssuerRegistry,
    registry_from_documents,
    tenant_labels,
)
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator

from ...tokens import Keypair

CORP = "https://idp.corp.test"
ACME = "https://idp.acme.test"


def _doc(issuer: str, **extra: object) -> dict[str, object]:
    return {"issuer": issuer, "audience": "acp", "jwks_url": f"{issuer}/keys", **extra}


def test_a_registration_carries_its_tenant() -> None:
    [registration] = registry_from_documents(
        [_doc(ACME, tenant="acme")], default_algorithms=["RS256"], leeway=30.0
    )
    assert registration.tenant == "acme"


def test_no_tenant_key_means_no_tenant() -> None:
    """The single-tenant gateway: the field simply is not there, and nothing
    downstream changes."""
    [registration] = registry_from_documents(
        [_doc(CORP)], default_algorithms=["RS256"], leeway=30.0
    )
    assert registration.tenant is None


@pytest.mark.parametrize(
    "bad",
    [
        "Acme",  # uppercase — one canonical spelling, not two
        "acme corp",  # whitespace
        "../etc",  # the label becomes a policy FILENAME
        "acme/globex",  # path separator
        "",  # empty is not a tenant
        "a" * 65,  # over the 64-character bound
        'ac"me',  # a quote, aimed at the JSON key encodings
        42,  # not a string at all
    ],
)
def test_a_label_that_could_forge_a_boundary_is_refused(bad: object) -> None:
    """The label reaches budget accounts, cache keys, audit records and a
    filename. One validation at configuration time, instead of four escaping
    disciplines forever."""
    with pytest.raises(ConfigurationError, match="tenant"):
        registry_from_documents([_doc(ACME, tenant=bad)], default_algorithms=["RS256"], leeway=30.0)


def test_hyphens_underscores_and_digits_are_fine() -> None:
    [registration] = registry_from_documents(
        [_doc(ACME, tenant="acme-eu_2")], default_algorithms=["RS256"], leeway=30.0
    )
    assert registration.tenant == "acme-eu_2"


def test_tenant_labels_collects_only_the_declared_ones() -> None:
    labels = tenant_labels([_doc(CORP), _doc(ACME, tenant="acme")])
    assert labels == frozenset({"acme"})


def test_tenant_labels_applies_the_same_validation() -> None:
    """Startup policy loading reads labels through this function *before*
    registrations are built; a bad label must fail here too, not only there."""
    with pytest.raises(ConfigurationError, match="tenant"):
        tenant_labels([_doc(ACME, tenant="../etc")])


def test_two_issuers_may_share_a_tenant() -> None:
    """A tenant with two identity providers (staff and CI, say) is one tenant:
    the same label on two registrations is one entry in the set and one policy
    file at startup."""
    labels = tenant_labels([_doc(ACME, tenant="acme"), _doc("https://ci.acme.test", tenant="acme")])
    assert labels == frozenset({"acme"})


# ---------------------------------------------------------------------------
# The stamp itself: verified token in, tenanted principal out
# ---------------------------------------------------------------------------

AUDIENCE = "agent-control-plane"


def _registration(issuer: str, keypair: Keypair, tenant: str | None) -> IssuerRegistration:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    return IssuerRegistration(
        policy=TokenPolicy(issuer=issuer, audience=AUDIENCE),
        keys=JwksCache(
            f"{issuer}/keys",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ),
        tenant=tenant,
    )


def _claims(issuer: str, **overrides: Any) -> dict[str, Any]:
    import time  # noqa: PLC0415

    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": "alice",
        "iss": issuer,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
    }
    payload.update(overrides)
    return payload


def test_the_principal_is_stamped_by_the_registration_that_verified_it(
    keypair: Keypair, other_keypair: Keypair
) -> None:
    """Two issuers, two tenants, one subject name. Each token is verified by
    its own registration and comes out carrying that registration's tenant —
    the identity the rest of the stack keys on."""
    validator = TokenValidator(
        issuers=IssuerRegistry(
            [
                _registration(ACME, keypair, "acme"),
                _registration(CORP, other_keypair, None),
            ]
        )
    )

    async def check() -> None:
        acme_alice = await validator.validate(keypair.sign(_claims(ACME), kid=keypair.kid))
        corp_alice = await validator.validate(
            other_keypair.sign(_claims(CORP), kid=other_keypair.kid)
        )
        assert acme_alice.tenant == "acme"
        assert acme_alice.subject == corp_alice.subject == "alice"
        assert corp_alice.tenant is None

    anyio.run(check)


def test_a_claimed_tenant_is_ignored(keypair: Keypair) -> None:
    """A token that *says* `tenant: globex` gets acme anyway. The claim is not
    read — the registration that cryptographically verified the token is the
    only voice, which is what makes the boundary as strong as the mix-up
    defence rather than as strong as the IdP's claim hygiene."""
    validator = TokenValidator(issuers=IssuerRegistry([_registration(ACME, keypair, "acme")]))

    async def check() -> None:
        principal = await validator.validate(
            keypair.sign(_claims(ACME, tenant="globex"), kid=keypair.kid)
        )
        assert principal.tenant == "acme"

    anyio.run(check)
