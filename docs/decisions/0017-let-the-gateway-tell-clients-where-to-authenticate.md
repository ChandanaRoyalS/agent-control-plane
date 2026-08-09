# ADR 0017 — Let the gateway tell clients where to authenticate

**Status:** accepted
**Date:** 2026-08-08

## Context

After task 23 the gateway trusts one or several authorization servers and cannot
cross their credentials. Nothing in that describes how a *client* learns which
server to get a token from. Today the answer is that somebody types an issuer
URL into the agent's configuration.

That is fine when one team runs one agent against one gateway. It stops being
fine at the scale MCP assumes, where an agent platform connects to servers it
did not know about at build time. A client that must be pre-configured with an
identity provider per server cannot connect to a server it has just discovered,
which makes every new integration a config change in two places instead of one.

There is a second cost, quieter and worse. A hand-configured issuer is a
hand-maintained copy of a fact the gateway already knows. When the gateway
changes authorization server, every client's copy is wrong, and the symptom on
the client's side is its own perfectly valid token being rejected — a failure
that reads like a client bug and is not.

RFC 9728 defines the fix, and the direction is the interesting part.

## Decision

**The gateway publishes a protected resource metadata document**, unsigned JSON,
at the RFC 9728 well-known location derived from its own resource identifier.
The document names the authorization servers a client may authenticate against.

**Every 401 carries `WWW-Authenticate: Bearer resource_metadata="<url>"`**
(RFC 9728 §5.1). A refusal becomes an instruction: the client fetches the URL,
reads `authorization_servers`, runs RFC 8414 discovery against one of them —
task 23's code from the other side of the wire — and comes back with a token.

**The document's `authorization_servers` is `IssuerRegistry.issuers`**, not a
separately configured list.

**The metadata path is the only unauthenticated path, and it is derived rather
than configured.** `AuthenticationMiddleware` takes the `ProtectedResource`
itself and exempts exactly its `metadata_path`, matched by exact string
equality.

**The resource identifier is a required, validated, public URI.** Absolute,
`https` outside loopback, no fragment, no query. Setting it without any
authorization server configured is a startup failure.

## Why the exemption is derived and not a list

The obvious implementation is `public_paths: list[str]` on the middleware, read
from config. It is one line shorter and it is the wrong shape.

An allow-list is a place where a second entry can be added by somebody who does
not have the middleware open in front of them, and "which routes skip
authentication" is not a question that should be answerable by editing a config
file. Deriving the exemption from the document means the set has exactly one
member, that member is the endpoint whose entire purpose is to be readable
without a credential, and serving it and exempting it cannot come apart — pass
no `ProtectedResource` and there is neither a route nor an exemption.

The matching is exact string equality against that one member, never
`startswith`. A prefix test on an allow-listed path is a classic bypass: the
guard reads "public" and the router reads something else about the same string.
Exact matching fails closed for every encoding trick, dot segment, trailing
slash and case variation, because anything the path is not spelled as simply
does not match and gets authenticated like every other request.

## The reconnaissance trade, made explicitly

This document names an organisation's authorization servers to anyone who asks.
ADR 0010 made the *opposite* call about the metrics endpoint — every upstream
name, every tool name, every currently-failing dependency — and put it behind a
loopback-only listener.

The two are consistent, and the distinguishing question is who the legitimate
reader is. A scrape endpoint enumerating brokered systems has no legitimate
anonymous reader; anyone entitled to it can be given a network path. This
document has almost nothing *but* anonymous readers, because a client that could
already authenticate does not need it. An authorization server's own metadata is
public for the same reason.

What is *not* in the document matters as much as what is: nothing about
upstreams, tools, or the gateway's internal state. A test asserts the emitted
keys are a subset of the fields RFC 9728 defines, so a future field cannot be
added here without that assertion being edited deliberately.

## Why the resource identifier is also the audience

They are the same string on purpose. A client passes it as RFC 8707's `resource`
parameter, the authorization server copies it into `aud`, and task 22 checks
`aud`. A client that follows the chain from a 401 to a token therefore ends up
holding exactly the audience this gateway demands, with nothing hardcoded
anywhere along the way. That is also the seam task 25 uses when it exchanges an
inbound token for a per-upstream one.

When the configured resource identifier is not among the audiences any
registered issuer will mint for, startup warns. Every step of the discovery
chain works and only the last one fails, so without the warning the operator's
evidence is a token rejected for the wrong `aud` and no indication that the
published document caused it.

## Alternatives considered

**Configure the authorization servers for the document separately.** Two lists
that must be kept in step eventually are not, and the failure lands on the
client: sent to a server this gateway does not trust, it sees its own good token
rejected. The registry is the fact; the document is a view of it.

**Make `ACP_AUTH_RESOURCE` part of the all-or-nothing identity rule.** Tempting,
because this project treats half-configured authentication as the worst
available state. It does not apply: publishing metadata is a convenience for
clients, not a control. A gateway without it validates tokens exactly as
strictly. So it is optional, and startup warns — the same treatment as an
inert drift detector, and for the same reason.

**Refuse to start when the resource identifier is not one of the audiences.**
Rejected. Plenty of authorization servers identify a resource by an opaque
client ID rather than by its URL, and that is a legitimate deployment; it just
means clients have to be told, which is the thing this document was meant to
stop being necessary. A refusal would make a working configuration unstartable.

**Serve the document on the admin listener.** RFC 9728 requires it at the
resource's own origin, and it would be wrong even if it did not: the whole point
is that a client which cannot yet authenticate can reach it, and the admin
listener is loopback-bound precisely so arbitrary clients cannot.

**Build the document per request.** It is derived entirely from startup
configuration and cannot change while the process runs, so this would be work
done to produce a constant — and it would make the cost of the one endpoint
anybody can reach proportional to how often they reach it. It is rendered once
and served verbatim, with `Cache-Control` so a client does not re-fetch after
every 401.

**Emit optional fields as empty arrays.** `"scopes_supported": []` is a claim:
that this resource has no scopes. Until Phase 3 defines them, saying nothing is
the accurate statement, and a client reading an empty array may reasonably stop
asking.

**Advertise the RFC 6750 query and form-body bearer methods.** Both write a
credential into access logs, proxy request lines and `Referer` headers. The
middleware reads the `Authorization` header and nothing else, and the document
says `["header"]` — a test drives `_bearer_token` with a query-string scope to
assert the two statements are the same statement, because a capability document
that describes a different program than the one serving it is worse than none.

**Append the well-known segment, OIDC-style.** RFC 9728 §3.1 *inserts* it, like
RFC 8414. Appending would put the document inside the resource's own path space,
where it collides with the resource's routes and where two protected resources
on one host cannot be told apart.

**Emit a relative URL in the challenge.** RFC 9728 §5.1 wants an absolute one,
and a client behind a TLS-terminating proxy cannot reliably reconstruct the
origin it reached the gateway on. The resource identifier is the one setting
that knows the public origin, which is also why it is configured separately from
the interface the process binds.

**Emit `resource_metadata` even with no document configured.** A challenge
pointing at a URL that answers 404 is worse than one pointing at nothing: it
sends the client down a discovery path that ends nowhere, and the client cannot
tell that from a gateway that is broken.

## Consequences

**`ACP_AUTH_RESOURCE` is new, optional, and warned about when absent.** It must
be the public URL an agent reaches the gateway on, which on anything but a
laptop is not the interface it binds.

**`build_app` and `gateway_from_configs` take a `resource`.** One object adds
the route and defines the exemption, so the two cannot drift.

**The metadata route is inserted at the front of the router**, not appended. The
SDK is free to mount its transport at the root, and a route added after a
catch-all mount never matches — a silent 404 on the one endpoint whose job is to
be findable by a client that knows nothing else.

**This route is not covered by the SDK's DNS-rebinding host allow-list**, which
applies to the transport it wraps. It serves a static, public, side-effect-free
document, so a browser reaching it learns only what the specification says
should be public. Worth knowing rather than worth fixing.

**Phase 2's remaining work has a place to attach.** `scopes_supported` is empty
until Phase 3 defines a policy vocabulary, and the resource identifier is
already the value task 25 will send as RFC 8707's `resource` parameter.
