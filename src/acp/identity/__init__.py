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

What lands here later in the phase: issuer validation binding credentials to the
authorization server that issued them (task 23, RFC 9207), protected resource
metadata so clients can discover that server (task 24, RFC 9728), and token
exchange minting a short-lived credential scoped to one upstream (task 25,
RFC 8693 with RFC 8707 resource indicators).

The invariant the whole security model rests on, stated before there is any code
that could violate it: **no inbound token is ever forwarded upstream.** There is
a test that asserts it rather than a comment claiming it.
"""

from acp.identity.asgi import ANONYMOUS, AuthenticationMiddleware
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
    "JwksCache",
    "Principal",
    "TokenPolicy",
    "TokenValidator",
    "bind_principal",
    "current_principal",
    "from_claims",
]
