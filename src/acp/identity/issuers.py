"""Trusted authorization servers, each bound to its own keys and audience.

Task 22 trusted exactly one issuer, and with one issuer there is nothing to
cross. The moment a gateway trusts two — a corporate directory and a partner's,
say, or a tenant per authorization server — a new class of mistake becomes
available, and it is the resource-server form of the **authorization server
mix-up** attack.

The mistake looks like this. Collect every trusted key into one bag. Verify the
signature against whichever key in the bag matches. *Then* read ``iss`` and
apply that issuer's rules. A token genuinely signed by the partner's key, but
claiming ``iss`` of the corporate directory, sails through: the signature is
valid, and every decision after it is made against the wrong authorization
server's registration. The partner can now mint corporate principals.

**A registration is indivisible.** Issuer, audience, key set and permitted
algorithms are configured together and used together. The ``iss`` claim selects
one registration and everything after that comes from *that* registration —
never from a merged view, never from a default.

**Selection reads an unverified claim, and that is safe here.** You cannot know
which key set to verify against without first looking at who the token says
issued it, and at that point nothing has been checked. The safety does not come
from the peek being trustworthy; it comes from what happens next. Having chosen
registration ``A`` because the token said ``A``, the signature must verify
against ``A``'s keys and ``iss`` must equal ``A``'s issuer. A token that lies
about its issuer selects a registration whose keys will not verify it. A token
that tells the truth gets the rules that belong to it. There is no ordering of
those two steps that lets them disagree.

Contrast the broken version, which is the same three facts in the wrong order:
verify first against anything, read ``iss`` after. That is a bag of keys, and a
bag of keys has no opinion about which server a token came from.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from acp.exceptions import AuthenticationError, ConfigurationError
from acp.identity.discovery import plaintext_permitted
from acp.identity.keys import (
    DEFAULT_CACHE_TTL,
    DEFAULT_MIN_REFRESH_INTERVAL,
    JwksCache,
)
from acp.identity.validator import TokenPolicy


@dataclass(frozen=True, slots=True)
class IssuerRegistration:
    """One authorization server, and everything that belongs to it.

    A dataclass rather than a tuple of arguments passed around together,
    precisely so there is no call site where the audience of one server can be
    combined with the keys of another. The type makes crossing them a thing you
    would have to construct deliberately.
    """

    policy: TokenPolicy
    keys: JwksCache

    @property
    def issuer(self) -> str:
        return self.policy.issuer

    @property
    def audience(self) -> str:
        return self.policy.audience


class IssuerRegistry:
    """Every authorization server this gateway will accept a token from."""

    def __init__(self, registrations: Iterable[IssuerRegistration]) -> None:
        self._by_issuer: dict[str, IssuerRegistration] = {}
        for registration in registrations:
            if registration.issuer in self._by_issuer:
                # Two registrations for one issuer means the second silently
                # wins, and which one that is depends on file ordering. When the
                # thing being chosen between is "which audience must a token
                # carry", ambiguity is not a tie to be broken.
                msg = (
                    f"issuer {registration.issuer!r} is registered more than once; "
                    f"each authorization server must appear exactly once"
                )
                raise ConfigurationError(msg)
            self._by_issuer[registration.issuer] = registration

        if not self._by_issuer:
            msg = "an issuer registry needs at least one authorization server"
            raise ConfigurationError(msg)

    def __len__(self) -> int:
        return len(self._by_issuer)

    def __iter__(self) -> Iterator[IssuerRegistration]:
        return iter(self._by_issuer.values())

    @property
    def issuers(self) -> list[str]:
        return sorted(self._by_issuer)

    def registration_for(self, issuer: str | None) -> IssuerRegistration:
        """The registration for this issuer, or an authentication failure.

        Matched by exact string equality. RFC 8414 §2 defines the issuer as an
        identifier compared as a string, and normalising it here — trimming a
        trailing slash, lowercasing a host — would mean this gateway's idea of
        "the same authorization server" differed from the token's. Two systems
        disagreeing about identity is the whole subject of this module.
        """
        registration = self._by_issuer.get(issuer or "")
        if registration is None:
            # Deliberately does not name the issuers that *are* registered.
            # Which authorization servers an organisation trusts is a useful map
            # for somebody deciding where to attack next, and an unauthenticated
            # caller can ask this question as many times as they like.
            raise AuthenticationError("the presented token is not valid")
        return registration

    async def aclose(self) -> None:
        for registration in self._by_issuer.values():
            await registration.keys.aclose()


def single_issuer(policy: TokenPolicy, keys: JwksCache) -> IssuerRegistry:
    """A registry of one, for the common deployment and for tests."""
    return IssuerRegistry([IssuerRegistration(policy=policy, keys=keys)])


def registry_from_documents(
    documents: Iterable[Mapping[str, object]],
    *,
    default_algorithms: Iterable[str],
    leeway: float,
    cache_ttl: float = DEFAULT_CACHE_TTL,
    min_refresh_interval: float = DEFAULT_MIN_REFRESH_INTERVAL,
    insecure_hosts: Iterable[str] = (),
) -> list[IssuerRegistration]:
    """Build registrations from parsed configuration, without touching the network.

    Split out from the loader so the shape of the configuration and the reading
    of a file are testable apart from each other, and so a `jwks_url` that has
    to be discovered can be filled in by the caller before this runs.
    """
    registrations: list[IssuerRegistration] = []
    for index, document in enumerate(documents):
        label = document.get("issuer") or f"#{index}"
        issuer = _required(document, "issuer", label)
        audience = _required(document, "audience", label)
        jwks_url = _required(document, "jwks_url", label)
        _reject_plaintext_keys(jwks_url, label, insecure_hosts)
        algorithms = document.get("algorithms") or list(default_algorithms)
        if not isinstance(algorithms, list):
            msg = f"issuer {label!r}: `algorithms` must be a list"
            raise ConfigurationError(msg)

        registrations.append(
            IssuerRegistration(
                policy=TokenPolicy(
                    issuer=issuer,
                    audience=audience,
                    algorithms=tuple(str(a) for a in algorithms),
                    leeway=leeway,
                ),
                keys=JwksCache(jwks_url, ttl=cache_ttl, min_refresh_interval=min_refresh_interval),
            )
        )
    return registrations


def _reject_plaintext_keys(jwks_url: str, label: object, insecure_hosts: Iterable[str]) -> None:
    """The same https rule discovery applies to metadata, applied to the keys.

    Discovery already refuses a plaintext issuer, but a configured `jwks_url`
    skips discovery entirely — so until task 26 this check existed on one of the
    two paths into the same decision, which is the shape of a control that looks
    present and is not. A key set fetched over plain HTTP can be replaced in
    transit by an attacker's key set, and every token afterwards verifies
    perfectly against it.
    """
    parts = urlsplit(jwks_url)
    if parts.scheme == "https" or plaintext_permitted(parts.hostname, insecure_hosts):
        return
    msg = (
        f"issuer {label!r}: `jwks_url` {jwks_url!r} must use https. A key set fetched "
        f"over plain HTTP can be swapped in transit, and every token afterwards "
        f"verifies perfectly against the attacker's keys."
    )
    raise ConfigurationError(msg)


def _required(document: Mapping[str, object], field: str, label: object) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        msg = f"issuer {label!r} is missing a non-empty {field!r}"
        raise ConfigurationError(msg)
    return value
