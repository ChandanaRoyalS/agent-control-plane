"""Prove the identity stack works against a real authorization server.

Run against a stack brought up with `docker compose up -d --wait`:

    uv run python scripts/identity_smoke.py

Everything in tasks 22 to 24 is covered by unit and integration tests, and every
one of those tests validates a token this repository signed, against a key set
this repository served, from an issuer this repository invented. That proves the
code is self-consistent. It cannot prove the code is *right*, because a mock
that agrees with your client proves only that you wrote both — the lesson from
task 13, restated with a real identity provider on the other end.

So this file asks the questions only a real server can answer:

1. Does the gateway publish RFC 9728 metadata naming the authorization server?
2. Does an unauthenticated request get a challenge that points at it?
3. Does that server's own metadata declare the same issuer the gateway trusts —
   RFC 8414 §3.3, checked here from the *client's* side of the wire?
4. Does Keycloak actually mint the audience the gateway demands? (This is the
   check that fails when the realm's audience mapper is missing, and it fails
   with a message saying so rather than an opaque 401.)
5. Does a real token get through?
6. Does it work for a second, different person?
7. Is a real, correctly signed token from an authorization server the gateway
   does not trust refused? Not a forgery — a genuine token from Keycloak's own
   `master` realm. This is ADR 0016's whole argument, tested for the first time
   against something that did not come from this repository.
8. Is a token whose signature has been altered refused?
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

from keycloak_token import access_token, claims, untrusted_token

GATEWAY = os.environ.get("ACP_SMOKE_GATEWAY", "http://127.0.0.1:8080")
KEYCLOAK = os.environ.get("ACP_SMOKE_KEYCLOAK", "http://127.0.0.1:8081")

EXPECTED_ISSUER = os.environ.get("ACP_SMOKE_ISSUER", "http://keycloak:8080/realms/acp")
EXPECTED_AUDIENCE = os.environ.get("ACP_SMOKE_RESOURCE", "http://localhost:8080/mcp")
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"

PROTOCOL_VERSION = "2026-07-28"
UNAUTHORIZED = 401

failures: list[str] = []


def report(ok: bool, label: str, detail: str = "") -> None:
    print(f"{'  ok  ' if ok else ' FAIL '} {label}{f' — {detail}' if detail else ''}")
    if not ok:
        failures.append(label)


def get(url: str, token: str | None = None) -> tuple[int, dict[str, str], bytes]:
    """A GET that returns the status rather than raising on 4xx.

    The status code *is* the assertion in most of this file, and urllib's
    default of raising for anything above 399 would turn the interesting
    outcomes into exceptions.
    """
    request = urllib.request.Request(url)  # noqa: S310 — fixed http URLs from config
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def mcp_list_tools(token: str | None) -> tuple[int, dict[str, str], dict[str, Any]]:
    """One real MCP request, with the envelope the 2026-07-28 revision demands."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "acp-identity-smoke",
                    "version": "0",
                },
            }
        },
    }
    request = urllib.request.Request(  # noqa: S310
        f"{GATEWAY}/mcp",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/list",
        },
        method="POST",
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return response.status, dict(response.headers), _decode(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), {}


def _decode(payload: str) -> dict[str, Any]:
    for line in payload.splitlines():
        if line.startswith("data:"):
            parsed: dict[str, Any] = json.loads(line[5:].strip())
            return parsed
    decoded: dict[str, Any] = json.loads(payload)
    return decoded


def tamper(token: str) -> str:
    """Flip one character of the signature, leaving everything else intact.

    A token that is correct in every way a human reading it would notice, and
    wrong in the only way that counts.
    """
    header, payload, signature = token.split(".")
    flipped = ("B" if signature[0] != "B" else "C") + signature[1:]
    return f"{header}.{payload}.{flipped}"


def check_metadata_is_public() -> None:
    status, _, body = get(f"{GATEWAY}{METADATA_PATH}")
    document = json.loads(body) if status == 200 else {}  # noqa: PLR2004
    servers = document.get("authorization_servers") or []
    report(
        status == 200 and servers == [EXPECTED_ISSUER],  # noqa: PLR2004
        "the gateway publishes RFC 9728 metadata, unauthenticated",
        f"HTTP {status}, authorization_servers={servers}",
    )


def check_challenge_points_at_it() -> None:
    status, headers, _ = mcp_list_tools(None)
    challenge = headers.get("WWW-Authenticate", "")
    report(
        status == UNAUTHORIZED and METADATA_PATH in challenge,
        "an unauthenticated request is challenged, with a discovery URL",
        f"HTTP {status}: {challenge or '(no challenge header)'}",
    )


def check_the_server_declares_itself() -> None:
    """RFC 8414 §3.3, from the client's side.

    The gateway makes this check at startup and refuses to serve if it fails.
    Making it here as well is not redundant: it is the difference between "our
    code agrees with itself" and "the server on the other end really does name
    the issuer we trust", and it is the check that catches a Keycloak whose
    hostname configuration has drifted.
    """
    url = f"{KEYCLOAK}/realms/acp/.well-known/openid-configuration"
    status, _, body = get(url)
    document = json.loads(body) if status == 200 else {}  # noqa: PLR2004
    declared = document.get("issuer")
    report(
        declared == EXPECTED_ISSUER,
        "Keycloak's metadata declares the issuer the gateway trusts",
        f"declared={declared!r} expected={EXPECTED_ISSUER!r}",
    )


def check_the_audience_mapper_is_doing_its_job(token: str) -> None:
    """The single likeliest reason a token is rejected, given its own check.

    Keycloak does not put an arbitrary audience in a token unless the realm
    tells it to. Without the mapper the token's `aud` is `account`, the gateway
    refuses it — correctly — and the operator sees a 401 with no indication that
    the cause is three files away in a realm export.
    """
    payload = claims(token)
    audience = payload.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    report(
        payload.get("iss") == EXPECTED_ISSUER and EXPECTED_AUDIENCE in audiences,
        "Keycloak mints the issuer and audience the gateway expects",
        f"iss={payload.get('iss')!r} aud={audiences}",
    )


def check_a_real_token_gets_through(token: str, who: str) -> None:
    status, _, body = mcp_list_tools(token)
    tools = [t["name"] for t in body.get("result", {}).get("tools", [])]
    report(
        status == 200 and len(tools) > 0,  # noqa: PLR2004
        f"a real token for {who} reaches the upstreams",
        f"HTTP {status}, {len(tools)} tools",
    )


def check_an_untrusted_issuer_is_refused() -> None:
    try:
        foreign = untrusted_token()
    except RuntimeError as exc:
        report(False, "a token from an untrusted issuer is refused", f"could not mint one: {exc}")
        return

    status, _, _ = mcp_list_tools(foreign)
    report(
        status == UNAUTHORIZED,
        "a genuine token from an untrusted authorization server is refused",
        f"HTTP {status} (master realm, correctly signed, not registered)",
    )


def check_a_tampered_signature_is_refused(token: str) -> None:
    status, _, _ = mcp_list_tools(tamper(token))
    report(status == UNAUTHORIZED, "a tampered signature is refused", f"HTTP {status}")


def main() -> int:
    try:
        alice = access_token("alice")
        bob = access_token("bob")
    except (RuntimeError, urllib.error.URLError, OSError) as exc:
        print(f"could not obtain a token from Keycloak at {KEYCLOAK}: {exc}", file=sys.stderr)
        print("is the stack up? `make up`", file=sys.stderr)
        return 1

    check_metadata_is_public()
    check_challenge_points_at_it()
    check_the_server_declares_itself()
    check_the_audience_mapper_is_doing_its_job(alice)
    check_a_real_token_gets_through(alice, "alice")
    check_a_real_token_gets_through(bob, "bob")
    check_an_untrusted_issuer_is_refused()
    check_a_tampered_signature_is_refused(alice)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s) — {'; '.join(failures)}", file=sys.stderr)
        return 1
    print("all identity checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
