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

What lands here later in the phase: protected resource metadata so clients can
discover that server (task 24, RFC 9728), and token exchange minting a
short-lived credential scoped to one upstream (task 25, RFC 8693 with RFC 8707
resource indicators).

The invariant the whole security model rests on, stated before there is any code
that could violate it: **no inbound token is ever forwarded upstream.** There is
a test that asserts it rather than a comment claiming it.
"""

from acp.identity.asgi import ANONYMOUS, AuthenticationMiddleware
from acp.identity.discovery import ProviderMetadata, discover
from acp.identity.issuers import IssuerRegistration, IssuerRegistry, single_issuer
from acp.identity.keys import JwksCache
from acp.identity.principal import (
    Actor,
    Principal,
    bind_principal,
    current_principal,
    from_claims,
)
from acp.identity.validator import DEFAULT_ALGORITHMS, TokenPolicy, TokenValidator

__all__ = [
    "ANONYMOUS",
    "DEFAULT_ALGORITHMS",
    "Actor",
    "AuthenticationMiddleware",
    "IssuerRegistration",
    "IssuerRegistry",
    "JwksCache",
    "Principal",
    "ProviderMetadata",
    "TokenPolicy",
    "TokenValidator",
    "bind_principal",
    "current_principal",
    "discover",
    "from_claims",
    "single_issuer",
]
