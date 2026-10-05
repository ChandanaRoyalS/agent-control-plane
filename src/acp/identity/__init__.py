"""Who the gateway is acting for: caller identity, trusted issuers and token exchange.

`validator` resolves a token to a subject (the human) and an actor (the workload, RFC 8693
``act``). `issuers` selects one indivisible issuer registration by the token's ``iss``;
`discovery` verifies the issuer binding (RFC 8414 §3.3). `resource` publishes RFC 9728
metadata whose identifier is the audience a token must carry. `exchange` mints a
short-lived per-upstream credential (RFC 8693 with RFC 8707). Invariant, asserted by a
test: no inbound token is ever forwarded upstream.
"""

from acp.identity.asgi import ANONYMOUS, AuthenticationMiddleware
from acp.identity.discovery import ProviderMetadata, discover
from acp.identity.exchange import (
    ExchangedCredentials,
    ExchangedToken,
    TokenExchanger,
    require_token_endpoints,
)
from acp.identity.issuers import IssuerRegistration, IssuerRegistry, single_issuer
from acp.identity.keys import JwksCache
from acp.identity.principal import (
    Actor,
    Principal,
    bind_principal,
    bind_subject_token,
    current_principal,
    current_subject_token,
    from_claims,
)
from acp.identity.resource import (
    BEARER_METHODS,
    WELL_KNOWN_SEGMENT,
    ProtectedResource,
    metadata_route,
    protected_resource,
)
from acp.identity.validator import DEFAULT_ALGORITHMS, TokenPolicy, TokenValidator

__all__ = [
    "ANONYMOUS",
    "BEARER_METHODS",
    "DEFAULT_ALGORITHMS",
    "WELL_KNOWN_SEGMENT",
    "Actor",
    "AuthenticationMiddleware",
    "ExchangedCredentials",
    "ExchangedToken",
    "IssuerRegistration",
    "IssuerRegistry",
    "JwksCache",
    "Principal",
    "ProtectedResource",
    "ProviderMetadata",
    "TokenExchanger",
    "TokenPolicy",
    "TokenValidator",
    "bind_principal",
    "bind_subject_token",
    "current_principal",
    "current_subject_token",
    "discover",
    "from_claims",
    "metadata_route",
    "protected_resource",
    "require_token_endpoints",
    "single_issuer",
]
