"""Who the gateway is acting for — Phase 2, tasks 22 onward.

The problem in one sentence: an agent wired into internal systems holds one
credential per system carrying the union of every permission any user might
need, so the same request reaches the same data whether it was made for an
intern or for the CFO. There is no principal in that picture, only an agent.

This package establishes one. Task 22 validates the token an agent presents and
resolves it to a **subject** — the human the work is for — and an **actor**, the
workload doing it, using RFC 8693's ``act`` claim rather than a bespoke shape.
Both halves matter and neither substitutes for the other: what may be read is a
question about the subject, and which agent may act at all is a question about
the actor.

Task 23 makes that safe to do for more than one authorization server at a time.
Each trusted issuer is an indivisible registration — issuer, audience, key set
and algorithms configured and used together — selected by the token's own ``iss``
before any rule is applied, so a credential from one server can never be judged
by another's rules. Where the binding is verified rather than merely asserted is
discovery: RFC 8414 §3.3 requires an authorization server's metadata to name the
same issuer the document was fetched for.

Task 24 turns that outward. A client no longer has to be configured with the
list of authorization servers a gateway trusts: a 401 carries the URL of an
RFC 9728 protected resource document, the document names the servers, and the
client runs task 23's discovery against one of them from the other side of the
wire. The identifier that document publishes is also the audience a token for
this gateway must carry, which is the seam task 25 uses.

What lands here later in the phase: token exchange minting a short-lived
credential scoped to one upstream (task 25, RFC 8693 with RFC 8707 resource
indicators).

The invariant the whole security model rests on, stated before there is any code
that could violate it: **no inbound token is ever forwarded upstream.** There is
a test that asserts it rather than a comment claiming it.
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
