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

Task 27 adds the questions that only the *upstream* can answer, read from the
mock fleet's `/debug/credential` endpoint:

9.  Did the upstream receive a credential at all?
10. Is it a *different* token from the one the caller presented — the invariant
    the entire security model rests on?
11. Is its `aud` this upstream alone, so it cannot be replayed against another?
12. Does it still name the human, with the gateway recorded as the actor?
13. Do two different upstreams receive two different credentials?

Task 28 adds the one that a conformant server would make redundant and this one
does not:

14. Is neither upstream's credential *also* valid at the other? Keycloak accepts
    RFC 8707's `resource` and discards it (ADR 0020), so the scope is real only
    because the gateway checks what it was granted rather than what it asked for.

Task 30 adds the two that only exist once credentials are held between calls:

15. Does a repeat call reuse the cached credential, rather than the cache being
    a correct-looking structure that never hits?
16. Does a *second caller* get their own credential? This is the one that
    matters. A cache keyed on the upstream alone hands bob a credential minted
    for alice — fast, functional, and wrong in the audit log.
"""

from __future__ import annotations

import hashlib
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
MOCK_A = os.environ.get("ACP_SMOKE_MOCK_A", "http://127.0.0.1:9101")
MOCK_B = os.environ.get("ACP_SMOKE_MOCK_B", "http://127.0.0.1:9102")

PROTOCOL_VERSION = "2026-07-28"
UNAUTHORIZED = 401

failures: list[str] = []


def report(ok: bool, label: str, detail: str = "") -> None:
    print(f"{'  ok  ' if ok else ' FAIL '} {label}{f' — {detail}' if detail else ''}")
    if not ok:
        failures.append(label)


def headers_of(message: Any) -> dict[str, str]:
    """Response headers, keyed in lower case.

    `dict(HTTPMessage)` looks harmless and quietly throws away the one property
    HTTP headers have: RFC 9110 §5.1 makes field names case-insensitive, and
    urllib's own `HTTPMessage` honours that — a plain dict built from it does
    not. The gateway sends `www-authenticate` in lower case, so a lookup for
    `WWW-Authenticate` against that dict returns nothing and the check reports a
    missing header on a response that has one.

    That is exactly what happened on the first green-but-for-one CI run, and it
    is worth the named function: every header read in this file goes through it.
    """
    return {name.lower(): value for name, value in message.items()}


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
            return response.status, headers_of(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, headers_of(exc.headers), exc.read()


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
            return response.status, headers_of(response.headers), _decode(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, headers_of(exc.headers), {}


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
    """RFC 9728 §5.1 — the 401 has to say where to go, not merely say no.

    On failure this prints every header name it did receive. "No challenge
    header" and "a challenge header I looked up wrongly" are indistinguishable
    otherwise, and the second is what happened the first time this ran.
    """
    status, headers, _ = mcp_list_tools(None)
    challenge = headers.get("www-authenticate", "")
    detail = challenge or f"(no challenge; headers were: {', '.join(sorted(headers))})"
    report(
        status == UNAUTHORIZED and METADATA_PATH in challenge,
        "an unauthenticated request is challenged, with a discovery URL",
        f"HTTP {status}: {detail}",
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


def credential_seen_by(base: str) -> dict[str, Any]:
    status, _, body = get(f"{base}/debug/credential")
    return json.loads(body) if status == 200 else {}  # noqa: PLR2004


def call_a_tool(token: str, name: str) -> tuple[int, str]:
    """One `tools/call`, which is what makes an upstream actually be reached.

    `tools/list` is served from the catalogue cache once the health prober has
    warmed it, so it may never touch an upstream at all — the same property that
    made the fan-out invisible in traces until probing was turned off. A tool
    call always goes.

    **`Mcp-Name` is not optional.** The 2026-07-28 revision routes on
    `Mcp-Method` and `Mcp-Name`, and a server verifies both against the body —
    a header claiming a name the body does not contain is itself a mismatch
    (ADR 0008). Omitting it here produced a 400 before any upstream was reached,
    and five checks that all reported "no credential" for a request that was
    never made. The gateway was right; the client was writing a request no real
    client sends, which is the exact thing ADR 0008 exists to catch.

    Returns the body alongside the status, because a 400 that does not say why
    is a check that turns one bug into an afternoon.
    """
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": {"query": "retention"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "acp-identity-smoke",
                    "version": "0",
                },
            },
        },
    }
    request = urllib.request.Request(  # noqa: S310
        f"{GATEWAY}/mcp",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": name,
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return int(response.status), response.read().decode()[:200]
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode(errors="replace")[:200]


def check_the_upstream_gets_a_credential(token: str) -> None:
    status, body = call_a_tool(token, "mock-a__search")
    seen = credential_seen_by(MOCK_A)
    detail = f"HTTP {status}, present={seen.get('present')}"
    report(
        status == 200 and seen.get("present") is True,  # noqa: PLR2004
        "the upstream is reached with a credential",
        detail if status == 200 else f"{detail} — {body}",  # noqa: PLR2004
    )


def check_it_is_not_the_callers_token(token: str) -> None:
    """The invariant the entire security model rests on, observed from outside
    the gateway process for the first time.

    Every other check of this inspects a request the gateway built, using the
    same code path that builds it. This asks the upstream what it actually
    received, and compares the fingerprint against the caller's own token.
    """
    call_a_tool(token, "mock-a__search")
    seen = credential_seen_by(MOCK_A)
    caller = hashlib.sha256(token.encode()).hexdigest()[:16]

    report(
        bool(seen.get("fingerprint")) and seen["fingerprint"] != caller,
        "the upstream did NOT receive the caller's token",
        f"upstream saw {seen.get('fingerprint')!r}, caller presented {caller!r}",
    )


def check_the_credential_is_scoped_to_one_upstream(token: str) -> None:
    """RFC 8707's whole point, and task 28's subject from the other side: a
    credential minted for mock-a must be useless against mock-b."""
    call_a_tool(token, "mock-a__search")
    seen = credential_seen_by(MOCK_A)
    audience = seen.get("audience") or []

    report(
        audience == ["acp-upstream-mock-a"],
        "the credential names exactly one upstream",
        f"aud={audience}",
    )


def check_the_credential_still_names_the_human(token: str) -> None:
    """Delegation, not impersonation. The upstream must be able to log "alice,
    via the gateway" — an exchanged token whose subject became the gateway would
    have thrown away the only thing the whole phase exists to preserve."""
    call_a_tool(token, "mock-a__search")
    seen = credential_seen_by(MOCK_A)

    report(
        seen.get("subject") == claims(token).get("sub"),
        "the credential still names the human it was minted for",
        f"upstream saw sub={seen.get('subject')!r}, actor={seen.get('actor')!r}",
    )


def check_two_upstreams_get_two_credentials(token: str) -> None:
    """One credential reused across upstreams would mean a compromised mock-a
    could call mock-b as alice. Different fingerprints prove they are separate
    tokens; different audiences prove neither works in the other's place."""
    call_a_tool(token, "mock-a__search")
    call_a_tool(token, "mock-b__search")
    a, b = credential_seen_by(MOCK_A), credential_seen_by(MOCK_B)

    report(
        bool(a.get("fingerprint"))
        and bool(b.get("fingerprint"))
        and a["fingerprint"] != b["fingerprint"]
        and a.get("audience") != b.get("audience"),
        "each upstream receives its own credential",
        f"mock-a aud={a.get('audience')} mock-b aud={b.get('audience')}",
    )


def check_a_credential_does_not_open_two_doors(token: str) -> None:
    """Task 28's control, seen from outside.

    Keycloak accepts RFC 8707's `resource` and discards it, so a gateway that
    sent the parameter and trusted it would hand each upstream a credential that
    also works at the other — and log a success. What makes the scope real is
    that the gateway checks the credential it was *given*, so this asserts the
    property rather than the parameter: neither upstream's credential names the
    other's audience.
    """
    call_a_tool(token, "mock-a__search")
    a = credential_seen_by(MOCK_A)
    call_a_tool(token, "mock-b__search")
    b = credential_seen_by(MOCK_B)

    a_aud, b_aud = set(a.get("audience") or []), set(b.get("audience") or [])
    report(
        bool(a_aud) and bool(b_aud) and not (a_aud & b_aud),
        "neither credential is valid at the other upstream",
        f"mock-a aud={sorted(a_aud)} mock-b aud={sorted(b_aud)}",
    )


def check_a_repeat_call_reuses_the_credential(token: str) -> None:
    """That the cache is doing anything at all, proved from outside.

    Two calls, one fingerprint. This works as evidence only because a *fresh*
    exchange would produce a different fingerprint every time — Keycloak puts a
    `jti` in every token it mints, so two credentials for the same caller and
    the same upstream are still two different strings. An identical fingerprint
    therefore cannot be a coincidence; it is the same credential, served twice.

    The inverse is the interesting failure: a cache key that is too *specific*
    never hits, returns entirely correct credentials, breaks nothing, and simply
    sends every request to the authorization server. Nothing would ever report
    it. This check is what would.
    """
    call_a_tool(token, "mock-a__search")
    first = credential_seen_by(MOCK_A).get("fingerprint")
    call_a_tool(token, "mock-a__search")
    second = credential_seen_by(MOCK_A).get("fingerprint")

    report(
        bool(first) and first == second,
        "a repeat call reuses the cached credential",
        f"first={first!r} second={second!r}",
    )


def check_two_callers_never_share_a_credential(alice: str, bob: str) -> None:
    """The failure task 30 exists to not have, observed at the upstream.

    Key the cache on the upstream — the obvious thing, since what is cached is
    'the credential for mock-a' — and bob's call arrives at the upstream holding
    a credential whose `sub` is alice. It is fast. It returns data. Every
    functional test passes and the audit trail is wrong in the one way nobody
    goes looking for: mock-a's log says alice read a record bob asked for.

    Two assertions, because either alone can pass while the design is broken.
    The fingerprints must differ — two credentials, not one shared. And the
    subject the upstream saw for bob's call must be *bob*, which is the sentence
    the leak makes false.
    """
    call_a_tool(alice, "mock-a__search")
    seen_for_alice = credential_seen_by(MOCK_A)
    call_a_tool(bob, "mock-a__search")
    seen_for_bob = credential_seen_by(MOCK_A)

    distinct = bool(seen_for_alice.get("fingerprint")) and seen_for_alice[
        "fingerprint"
    ] != seen_for_bob.get("fingerprint")
    named_correctly = seen_for_bob.get("subject") == claims(bob).get("sub")

    report(
        distinct and named_correctly,
        "a second caller is not served the first one's credential",
        f"alice={seen_for_alice.get('fingerprint')!r} sub={seen_for_alice.get('subject')!r}; "
        f"bob={seen_for_bob.get('fingerprint')!r} sub={seen_for_bob.get('subject')!r}",
    )


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

    # Task 27 — what the upstream ends up holding.
    check_the_upstream_gets_a_credential(alice)
    check_it_is_not_the_callers_token(alice)
    check_the_credential_is_scoped_to_one_upstream(alice)
    check_the_credential_still_names_the_human(alice)
    check_two_upstreams_get_two_credentials(alice)
    check_a_credential_does_not_open_two_doors(alice)

    # Task 30 — the cache, and the one mistake in it that is a privilege
    # escalation rather than a performance regression.
    check_a_repeat_call_reuses_the_credential(alice)
    check_two_callers_never_share_a_credential(alice, bob)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s) — {'; '.join(failures)}", file=sys.stderr)
        return 1
    print("all identity checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
