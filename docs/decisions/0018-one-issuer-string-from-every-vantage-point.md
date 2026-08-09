# ADR 0018 — One issuer string from every vantage point, and one escape hatch on purpose

**Status:** accepted
**Date:** 2026-08-09

## Context

Tasks 22 to 24 built inbound identity: token validation, issuer binding,
discovery, protected resource metadata. Every one of those is covered by tests,
and every one of those tests validates a token this repository signed, against a
key set this repository served, from an issuer this repository invented.

That proves the code is self-consistent. It cannot prove the code is *right*.
The lesson is already written down from task 13 — *a mock that agrees with your
client proves only that you wrote both* — and it applies with full force to an
OAuth resource server, where every failure mode is somebody else's server
disagreeing with your assumptions.

Task 26 puts Keycloak in Compose. Two things went wrong immediately, before a
line of the compose file was written, and both are worth recording because both
are about the difference between a specification and a network.

## Problem one: an issuer is an identity, not an address

The gateway resolves the identity provider from inside the Compose network,
where it is `keycloak:8080`. A human gets a token from their laptop, where it is
`localhost:8081`. Those are the same server.

They are not the same issuer. ADR 0016 settled that issuers are compared as
exact strings with no normalisation, because normalising would mean this
gateway's notion of "the same authorization server" differed from the
specification's. So a token minted through one door and validated at the other
is a token from an unregistered issuer, and it is correctly refused.

The instinct is to make the gateway tolerant — accept either spelling, or
normalise the host. That is exactly the hole ADR 0016 exists to prevent, and
reintroducing it as a convenience for a demo would be the worst possible reason.

**Decision: Keycloak is told its hostname, and there is one string.**
`KC_HOSTNAME=http://keycloak:8080` fixes what Keycloak stamps into `iss`
regardless of which door a request arrived through. A token fetched from
`localhost:8081` still says `keycloak:8080`, because that is the server's
identity and `localhost:8081` is merely a route to it.

The cost is that the admin console's own links point at `keycloak:8080`, which
a browser on the host cannot resolve. That is real and it is the right trade:
identity is exact, addresses are many, and the thing that must be unambiguous
is the identity. The demo scripts fetch tokens through the published port and
work fine, because they only ever *post* to it.

## Problem two: the escape hatch you build on purpose

`http://keycloak:8080` is not `https`, and `keycloak` is not loopback. Discovery
refused it, correctly, at the first attempt — RFC 8414 §2 requires `https`, and
the loopback exemption exists because traffic that never leaves the machine has
no in-flight to be rewritten in. Container-to-container traffic is not that.

Three ways out were on the table.

**Add `keycloak` to `LOOPBACK_HOSTS`.** One line, and a lie. That set means "the
network cannot be observed here", `keycloak` does not, and the change would ship
to every deployment of this gateway forever.

**Disable certificate verification.** Broader than the problem, applies to every
host rather than one, and invisible in a config file — the person reading the
deployment would see nothing at all.

**Run Keycloak with TLS.** The purist answer, and it means generating a
certificate, mounting a CA into the gateway image, and adding a moving part to
the one command that is supposed to make this project runnable by a stranger.
It is the right answer for a production identity provider and the wrong one for
a demo realm on a laptop.

**Decision: `ACP_AUTH_INSECURE_ISSUER_HOSTS`, a list of hostnames, empty by
default.** Naming a host there permits plain HTTP for its metadata *and* its key
set, and nothing else. It is narrow, it is a hostname somebody typed, and
startup logs one warning per entry naming the host and the consequence.

The general principle: a system that makes a legitimate case impossible does not
prevent the workaround, it chooses the workaround for you — and the one people
reach for is always broader and quieter than the one you would have designed.

## What this closed on the way past

The `https` rule was enforced on the issuer in `discover()`, and skipped
entirely when `jwks_url` was configured by hand — the path that bypasses
discovery. So the rule existed on one of two routes into the same decision,
which is the shape of a control that looks present and is not. A key set fetched
over plain HTTP can be swapped in transit, and every token afterwards verifies
perfectly against the attacker's keys.

`registry_from_documents` now applies the same check to `jwks_url` on both
paths, using the same allow-list.

## Problem three, smaller: refusing to start

Every task before this one ran unauthenticated when nothing was configured, with
a warning, because there was no identity provider to run against and refusing
would have meant the gateway could not run at all. Keycloak ended that excuse.

**Decision: `ACP_AUTH_REQUIRED`, defaulting to true.** Read the polarity
carefully, because it is the boolean task 22 argued against, inverted.
`ACP_AUTH_ENABLED=false` fails **open** when forgotten: a gateway serving
everything while its configuration claims otherwise. This fails **closed**. It
does not turn authentication on — only configuring a provider does that — it
*asserts* that one is configured, and forgetting to think about it produces a
gateway that will not start rather than one that will not check.

Unauthenticated remains a real, supported, loudly-logged mode. Entering it now
costs one line that a human wrote on purpose.

**And it went in the wrong place first, which is the more useful half of this.**
The check started in the settings validator, so a `GatewaySettings` could not be
constructed at all without an identity provider. That looked like the strictest
possible reading of fail-closed. It also broke `acp schemas capture` — a local
command that reads upstream catalogues, writes a baseline file, and has no
connection to authentication whatsoever — because it builds a settings object
like everything else does.

The claim being made is "this gateway must not *serve* unauthenticated". So it
belongs in `build_token_validator`, which runs when the gateway is about to
serve, and not at construction, which happens in every program that imports the
settings. The general form is worth keeping: **a rule enforced further out than
its own scope stops being a security property and becomes the reason somebody
switches it off.** A fail-closed control that makes unrelated work impossible
does not stay enabled.

It was caught by three CLI tests, and by nothing else — the failure is invisible
to anything that only exercises the serving path.

## Alternatives considered

**A healthcheck on the Keycloak container.** The gateway runs discovery at
startup before binding a port, so "is Keycloak answering" is a hard ordering
dependency. The usual expression of that is a `healthcheck` on Keycloak — which
means writing a probe out of whatever binaries that image happens to ship. It
has no curl and no wget, and the widely-copied answer is a shell one-liner
against `/dev/tcp` or a Java source file written to `/tmp` at probe time, both
of which break when somebody else's base image changes.

A one-shot `keycloak-ready` container built from *our* image polls the realm's
metadata endpoint until it answers. It needs nothing from Keycloak's image, and
when it fails the message is one we wrote. `depends_on:
service_completed_successfully` gives exactly the ordering, and `--wait` waits
for it.

**Let the gateway retry discovery instead of ordering the startup.** That would
make a gateway start successfully with an unverified idea of which keys to
trust, which is the property ADR 0016 spent a task establishing. Startup
discovery is fail-fast on purpose; the ordering belongs in the orchestrator.

**Commit no realm and document the console clicks.** The demo would then be
reproducible only by people who read carefully and click accurately. A committed
realm export is the difference between "the auth stack is reproducible from a
clone" and "the auth stack worked on my machine in August".

**Put the realm's commentary in the JSON as `_comment` keys.** A realm export is
deserialised strictly and an unknown key can fail the import. The commentary
lives in `config/keycloak/README.md`, and the JSON stays diffable against a real
export.

## Consequences

**The composed gateway now authenticates, so `compose_smoke.py` needs a token.**
That is deliberate rather than incidental: the stack smoke test can no longer
pass against a stack whose authentication is broken, which is the only way a
smoke test stays honest once the system grows a security boundary. It also
gained a check that an unauthenticated request is *refused* — cheap, and the
only thing in that file that would notice a gateway which starts believing it
authenticates and serves anyway.

**`identity_smoke.py` is new, and one of its checks is worth more than the rest
put together.** It obtains a genuine, correctly signed token from Keycloak's own
`master` realm — a real authorization server the gateway does not trust — and
asserts it is refused. Not a forgery, not a tampered signature: the exact thing
ADR 0016 says must not work, produced by something that did not come from this
repository.

**The realm ships two users.** Alice reads, Bob reads and writes. One user
proves a token validates; two are what Phase 2 has to end with, and the
difference between them is in git before there is a policy engine to act on it.

**Standard token exchange is pre-enabled on the agent client**, so task 27 needs
no realm change. It is a claim until task 27 proves it.

**A note for task 28.** Keycloak's token exchange names its target with a
*client ID*, not a URI, which is narrower than RFC 8707's resource indicator.
Whether it also accepts a `resource` parameter is a task 28 question; if it does
not, the deviation gets an ADR the way task 23's did.

**Monkeypatched fakes must mirror the real signature, keyword arguments
included.** `discover` gained `insecure_hosts`, and every test that patches it
broke with a `TypeError` naming the fake rather than the change. A fake that
accepts *less* than the thing it replaces fails only when a caller passes the
argument it lacks, which is the moment somebody adds one. The fakes in
`test_identity_wiring.py` now take the full signature and record what they were
given, so the next such addition is a test that asserts rather than one that
explodes.

**CI grew a minute.** The `image` job now boots Keycloak, imports a realm, waits
for it, and runs both smoke tests. The timeout went from 15 minutes to 20.
