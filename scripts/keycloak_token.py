"""Get a real access token out of the composed Keycloak.

Both a library and a command. As a command it prints a token for a user, which
is the fastest way to have something to paste into `curl`:

    uv run python scripts/keycloak_token.py            # alice
    uv run python scripts/keycloak_token.py bob        # bob
    uv run python scripts/keycloak_token.py --claims   # decoded, not the token

As a library it is what `compose_smoke.py` and `identity_smoke.py` both call,
so there is exactly one place that knows the demo client's name and secret.

**Everything here is a fixture.** The client secret and both passwords are
committed, in `config/keycloak/acp-realm.json`, on GitHub. They unlock a realm
containing two invented users and no data.

**Why `localhost:8081` here and `keycloak:8080` in the gateway's config.** They
are the same server reached from two places, and only one of those two strings
is its *identity*. Keycloak is told its hostname is `http://keycloak:8080`, so
that is what it stamps into `iss` no matter which door a request came through —
which is exactly what has to be true for an issuer to be an identity rather than
an address. A token fetched here therefore says `keycloak:8080`, and the gateway,
which resolves that name inside the Compose network, accepts it. See ADR 0018.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

KEYCLOAK = os.environ.get("ACP_SMOKE_KEYCLOAK", "http://127.0.0.1:8081")
REALM = os.environ.get("ACP_SMOKE_REALM", "acp")

CLIENT_ID = "acp-agent"
CLIENT_SECRET = "dev-only-not-a-secret"  # noqa: S105 — a fixture, committed on purpose;
# see config/keycloak/README.md. Suppressed rather than renamed because the rule is
# right and the exception is the thing worth writing down.

USERS = {"alice": "alice", "bob": "bob"}
"""The two demo users and their passwords. Two, not one, because Phase 2 has to
end with the same agent and the same tool producing different credentials for
different people — and that demo needs two people to be about."""


def token_endpoint(realm: str = REALM, base: str = KEYCLOAK) -> str:
    return f"{base}/realms/{realm}/protocol/openid-connect/token"


def post_form(url: str, fields: dict[str, str], *, timeout: float = 15.0) -> dict[str, Any]:
    """POST a form and parse the JSON, turning an HTTP error into a readable one.

    OAuth error bodies are the useful part of an OAuth failure and urllib throws
    them away by default — `HTTPError` carries the body but `str(exc)` does not
    show it. Almost every failure in this file is a 400 whose body says exactly
    what is wrong, so it is worth the four lines to surface it.
    """
    request = urllib.request.Request(  # noqa: S310 — fixed http URL from config
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            parsed: dict[str, Any] = json.loads(response.read())
            return parsed
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        msg = f"{url} answered HTTP {exc.code}: {body}"
        raise RuntimeError(msg) from exc


def access_token(username: str = "alice", password: str | None = None) -> str:
    """A token for a named user, via the direct access grant.

    Direct access grants are enabled on the demo client purely so this is one
    HTTP call. In production the flow is usually off and the token arrives from
    the agent platform — the gateway does not care which, because it only ever
    validates what it is handed.
    """
    payload = post_form(
        token_endpoint(),
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "username": username,
            "password": password or USERS.get(username, username),
        },
    )
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        msg = f"no access_token in the response for {username!r}: {payload}"
        raise RuntimeError(msg)
    return token


def untrusted_token() -> str:
    """A genuine, correctly signed token from an authorization server the gateway
    does not trust.

    Keycloak's own `master` realm, which every Keycloak has. This is the most
    valuable negative case in the project so far: not a forgery, not a tampered
    signature, but a *real* token from a *real* server — the thing ADR 0016 says
    must be refused, produced by something other than a test fixture written to
    agree with us.
    """
    payload = post_form(
        token_endpoint(realm="master"),
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.environ.get("ACP_SMOKE_KC_ADMIN", "admin"),
            "password": os.environ.get("ACP_SMOKE_KC_ADMIN_PASSWORD", "admin"),
        },
    )
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        msg = f"no access_token from the master realm: {payload}"
        raise RuntimeError(msg)
    return token


def claims(token: str) -> dict[str, Any]:
    """The payload, decoded and *not* verified.

    For assertions about what Keycloak minted, never for a trust decision. The
    gateway verifies; this reads. Keeping those two things in separate programs
    is the reason this one is allowed to be careless.
    """
    segment = token.split(".")[1]
    padded = segment + "=" * (-len(segment) % 4)
    decoded: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    return decoded


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    user = args[0] if args else "alice"
    token = access_token(user)
    if "--claims" in argv:
        print(json.dumps(claims(token), indent=2, sort_keys=True))
    else:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
