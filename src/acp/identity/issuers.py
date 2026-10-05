"""Trusted authorization servers, each bound to its own keys and audience.

Defends against authorization server mix-up. A registration (issuer, audience, keys,
algorithms) is indivisible, and the token's unverified ``iss`` selects exactly one. That
peek is safe because the signature must then verify against that registration's keys and
``iss`` must equal its issuer, so a lying token selects keys that will not verify it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
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
    """One authorization server and everything that belongs to it, kept together."""

    policy: TokenPolicy
    keys: JwksCache
    tenant: str | None = None
    """Tenant for this server's principals; ``None`` means not multi-tenant.

    Set on the registration, never read from a token claim, so a token cannot claim its
    way into another tenant.
    """

    token_endpoint: str = ""
    """RFC 8693 token endpoint (see `acp.identity.exchange`).

    Per registration, since an exchange must go back to the server that issued the token.
    """

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
                # A duplicate would silently win by file order.
                msg = (
                    f"issuer {registration.issuer!r} is registered more than once; "
                    f"each authorization server must appear exactly once"
                )
                raise ConfigurationError(msg)
            self._by_issuer[registration.issuer] = registration

        if not self._by_issuer:
            msg = "an issuer registry needs at least one authorization server"
            raise ConfigurationError(msg)

        unlabelled = sorted(r.issuer for r in self._by_issuer.values() if r.tenant is None)
        if len(unlabelled) > 1:
            # Unlabelled issuers would share the (tenant, subject) namespace in cache,
            # budgets and approvals: ADR 0051's failure via config (ADR 0070).
            msg = (
                f"issuers {unlabelled!r} have no `tenant` label: principals from "
                f"different authorization servers would share one namespace in the "
                f"cache, the budgets and the approval binding. Label all but at most "
                f"one of them."
            )
            raise ConfigurationError(msg)

    def __len__(self) -> int:
        return len(self._by_issuer)

    def __iter__(self) -> Iterator[IssuerRegistration]:
        return iter(self._by_issuer.values())

    @property
    def issuers(self) -> list[str]:
        return sorted(self._by_issuer)

    def registration_for(self, issuer: str | None) -> IssuerRegistration:
        """Return the registration for this issuer.

        Matched by exact string equality (RFC 8414 §2), with no normalisation.

        Raises:
            AuthenticationError: The issuer is not registered.
        """
        registration = self._by_issuer.get(issuer or "")
        if registration is None:
            # Never name the trusted issuers to an unauthenticated caller.
            raise AuthenticationError("the presented token is not valid")
        return registration

    def for_audience(self, audience: str) -> IssuerRegistry:
        """Return the same authorization servers, trusted for a different audience.

        Used for the operator channel; the audience keeps operator and agent tokens apart
        (RFC 8707). Key caches are shared, so never close the derived registry alone.

        Raises:
            ConfigurationError: An issuer already mints tokens for ``audience``, which
                would let an agent approve its own call (ADR 0049, ADR 0070).
        """
        colliding = sorted(
            r.issuer for r in self._by_issuer.values() if r.policy.audience == audience
        )
        if colliding:
            msg = (
                f"operator audience {audience!r} is also the gateway audience of "
                f"issuers {colliding!r}: a token for the gateway would also open the "
                f"approval channel, so an agent could approve its own call"
            )
            raise ConfigurationError(msg)
        return IssuerRegistry(
            replace(registration, policy=replace(registration.policy, audience=audience))
            for registration in self._by_issuer.values()
        )

    async def aclose(self) -> None:
        for registration in self._by_issuer.values():
            await registration.keys.aclose()


def single_issuer(policy: TokenPolicy, keys: JwksCache) -> IssuerRegistry:
    """Return a registry of one issuer."""
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

    A `jwks_url` needing discovery must be filled in by the caller first.
    """
    registrations: list[IssuerRegistration] = []
    for index, document in enumerate(documents):
        label = document.get("issuer") or f"#{index}"
        issuer = _required(document, "issuer", label)
        audience = _required(document, "audience", label)
        jwks_url = _required(document, "jwks_url", label)
        _reject_plaintext_keys(jwks_url, label, insecure_hosts)
        token_endpoint = document.get("token_endpoint")
        tenant = _tenant_label(document.get("tenant"), label)
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
                token_endpoint=token_endpoint if isinstance(token_endpoint, str) else "",
                tenant=tenant,
            )
        )
    return registrations


TENANT_LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
"""Lowercase slug, at most 64 characters.

Labels end up in budget accounts, cache keys, audit records and policy filenames, so they
are validated once here rather than escaped downstream.
"""


def tenant_labels(documents: Iterable[Mapping[str, object]]) -> frozenset[str]:
    """Return every tenant the issuer documents declare, validated.

    Used at startup before registrations are built, since policy loads first.
    """
    labels = set()
    for index, document in enumerate(documents):
        label = _tenant_label(document.get("tenant"), document.get("issuer") or f"#{index}")
        if label is not None:
            labels.add(label)
    return frozenset(labels)


def _tenant_label(value: object, label: object) -> str | None:
    """Return the validated tenant label, or ``None`` when not multi-tenant."""
    if value is None:
        return None
    if not isinstance(value, str) or not TENANT_LABEL.fullmatch(value):
        msg = (
            f"issuer {label!r}: `tenant` must be a lowercase slug "
            f"(letters, digits, `-`, `_`; max 64), got {value!r}. The label is "
            f"used in budget accounts, cache keys, audit records and policy "
            f"filenames, so it is validated here once rather than escaped in "
            f"four places forever."
        )
        raise ConfigurationError(msg)
    return value


def _reject_plaintext_keys(jwks_url: str, label: object, insecure_hosts: Iterable[str]) -> None:
    """Apply discovery's https rule to a configured `jwks_url`, which skips discovery."""
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
