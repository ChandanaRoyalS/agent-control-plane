# The demo realm

`acp-realm.json` is a Keycloak realm export, committed so that `docker compose
up` gives a working identity provider from a fresh clone with nobody clicking
through an admin console. The commentary lives here rather than in the JSON
because a realm export is deserialised strictly — an unknown `_comment` key can
fail the import, and a config file that has to be right is not the place to be
clever.

## Every secret in that file is public

They are in git, on GitHub, in a repository whose entire purpose is to be read.
They exist so a stranger can run the demo. Nothing there is a credential; they
are fixtures shaped like credentials, and the realm they unlock contains two
invented users and no data.

This is stated plainly because "committed secrets" is a real finding in real
reviews, and the difference between this and the finding is whether anybody
wrote down which one it is.

## Editing it does nothing to a running stack

Keycloak **skips the import when the realm already exists**. That is the right
default — it stops a restart from silently reverting whatever an operator did in
the console — and it means changing this file has no effect until the volume is
dropped:

```bash
make idp-reset      # down -v, then up: the realm is re-imported from this file
```

If a change to this file appears not to work, this is why, roughly nine times
out of ten.

## What is in it, and why

**Two clients.** `acp-agent` is the *workload identity* — the thing doing the
work, as opposed to the person it is being done for. Phase 2 keeps those as two
separate identities and neither substitutes for the other
([ADR 0015](../../docs/decisions/0015-two-identities-not-one.md)). It is
confidential rather than public for two reasons: Keycloak refuses standard token
exchange from a public client, which task 27 needs, and a workload identity
anyone can claim is not an identity.

`acp-gateway` exists to be *named*. Keycloak's token exchange takes a client ID
in its `audience` parameter, not an arbitrary URI, so the resource has to exist
as a client before anything can be exchanged toward it. It has no flows enabled
and is never logged into.

Worth flagging before task 28 rather than discovering during it: taking a client
ID there is Keycloak being narrower than RFC 8707, which lets the target be
named by URI. Whether it also accepts a `resource` parameter is a task 28
question, and if it does not, the deviation gets an ADR the way task 23's did.

**No browser flow.** `standardFlowEnabled` is false because there is no browser
here. An agent is not a user-facing application, and modelling it as one is how
agents end up holding a human's session.

`directAccessGrantsEnabled` is true so the demo script can get a token for a
named user in one HTTP call. In production that flow is usually off and the
token arrives from the agent platform instead — the gateway does not care
which, because it only ever validates what it is handed. It is on here so the
demo is one command rather than a browser dance nobody can automate.

**The audience mapper is the object most likely to be the reason a token is
rejected.** Keycloak does not put an arbitrary audience into a token unless it
is told to; without `acp-gateway-audience` the access token's `aud` is `account`
and the gateway refuses it — correctly, because a token minted for something
else is exactly what audience checking exists to catch.

Its value must equal `ACP_AUTH_RESOURCE` and `ACP_AUTH_AUDIENCE`. All three are
the same string on purpose: the gateway publishes it under RFC 9728, a client
asks for it as RFC 8707's `resource`, and the authorization server writes it
into `aud` ([ADR 0017](../../docs/decisions/0017-let-the-gateway-tell-clients-where-to-authenticate.md)).

**Two users, not one.** One user proves a token validates. Two users with
different roles are what Phase 2 has to *end* with — the same agent, the same
tool, two people, two demonstrably different upstream credentials. Alice reads;
Bob reads and writes. They exist now so that demo has something to be about
later, and so the difference between them is already in git before there is a
policy engine to act on it.

**Five-minute access tokens.** Short for a login session, about right for a
credential an automated agent holds, and comfortably longer than the 60 seconds
of clock skew the gateway tolerates. Short enough that watching one expire
during a demo takes five minutes rather than eight hours.

## Poking at it by hand

```bash
# a token for alice
docker compose exec -T keycloak \
  curl -s -d grant_type=password -d client_id=acp-agent \
       -d client_secret=dev-only-not-a-secret \
       -d username=alice -d password=alice \
       http://keycloak:8080/realms/acp/protocol/openid-connect/token | jq -r .access_token

# what the gateway will discover
docker compose exec -T keycloak \
  curl -s http://keycloak:8080/realms/acp/.well-known/openid-configuration | jq '{issuer, jwks_uri}'
```

Both run *inside* the network on purpose. See
[ADR 0018](../../docs/decisions/0018-one-issuer-string-from-every-vantage-point.md)
for why `keycloak:8080` and not `localhost`.
