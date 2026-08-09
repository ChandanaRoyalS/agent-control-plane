"""What does Keycloak actually do with RFC 8707's `resource` parameter?

Run against a stack brought up with `make up`:

    uv run python scripts/probe_resource_indicator.py

**This is a measurement, not a test.** It asserts nothing and always exits 0.
Its output decides how task 28 is implemented, which is the opposite of the
usual order and deliberately so.

The reason is a rule this project has already paid for once. Task 23's brief
named RFC 9207, which turned out to defend a redirect-flow client and never
reach a resource server; implementing it literally would have been a citation
with no control behind it — worse than none, because a reviewer believes it.
RFC 8707 is the same shape of risk. Adding a `resource` parameter, claiming
conformance, and never checking whether the server did anything with it is
indistinguishable from conformance right up until somebody depends on it.

So: send the parameter every way it could reasonably be sent, and read what
comes back out of the resulting token's `aud`.

What the answers mean
---------------------

**Honoured** — `resource` alone narrows `aud` the way `audience` does. The
gateway sends the URI, which is what RFC 8707 specifies, and any server that
implements the RFC behaves the same way.

**Ignored** — `resource` changes nothing; only `audience` narrows. The gateway
sends both: the URI because it is correct against a conformant server, the
client ID because it is what this one acts on. The ADR records that Keycloak is
narrower than the RFC, and the smoke test keeps asserting on `aud` rather than
on the parameter being present.

**Rejected** — sending it breaks the exchange. Then the gateway must *not* send
it to Keycloak, and the deviation gets written up the way task 23's was.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from keycloak_token import access_token, claims, post_form, token_endpoint

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 — a type URI

CLIENT_ID = "acp-gateway"
CLIENT_SECRET = "dev-only-not-a-secret-either"  # noqa: S105 — a committed fixture

MOCK_A = "acp-upstream-mock-a"
MOCK_B = "acp-upstream-mock-b"

RESOURCE_A = "https://mock-a.internal/mcp"
"""A URI that names no Keycloak client.

Deliberately not a client ID. If `aud` comes back containing this, Keycloak is
treating `resource` as RFC 8707 intends — the target is named by URI and need
not exist as a client at all.
"""


def exchange(subject_token: str, **extra: str) -> dict[str, Any]:
    """One exchange, returning a flat summary rather than raising."""
    form = {
        "grant_type": GRANT_TYPE,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        **extra,
    }
    try:
        payload = post_form(token_endpoint(), form)
    except RuntimeError as exc:
        return {"ok": False, "detail": str(exc)[:300]}

    token = payload.get("access_token")
    if not isinstance(token, str):
        return {"ok": False, "detail": f"no access_token: {payload}"}

    body = claims(token)
    audience = body.get("aud")
    return {
        "ok": True,
        "aud": audience if isinstance(audience, list) else [audience],
        "azp": body.get("azp"),
        "sub": body.get("sub"),
        "act": body.get("act"),
    }


CASES: list[tuple[str, dict[str, str]]] = [
    ("audience only (the task 27 baseline)", {"audience": MOCK_A}),
    ("resource only, naming a URI", {"resource": RESOURCE_A}),
    ("resource only, naming a client id", {"resource": MOCK_A}),
    ("both, agreeing", {"audience": MOCK_A, "resource": RESOURCE_A}),
    ("both, disagreeing", {"audience": MOCK_A, "resource": MOCK_B}),
    ("neither — what does an unscoped exchange return?", {}),
]


def classify(results: dict[str, dict[str, Any]]) -> str:
    """Read the four possible worlds off the results."""
    baseline = results["audience only (the task 27 baseline)"]
    uri_only = results["resource only, naming a URI"]
    both = results["both, agreeing"]

    if not baseline.get("ok"):
        return (
            "INCONCLUSIVE — even the task 27 baseline failed. "
            "Is the stack up, and is the realm current? `make idp-reset`"
        )
    if not both.get("ok"):
        return "REJECTED — sending `resource` breaks an exchange that works without it."
    if uri_only.get("ok") and RESOURCE_A in (uri_only.get("aud") or []):
        return "HONOURED — `resource` names the target by URI, as RFC 8707 specifies."
    if uri_only.get("ok"):
        return (
            "PARTIAL — `resource` is accepted but does not appear in `aud`. "
            "Read the audiences below before deciding."
        )
    return "IGNORED — `resource` is accepted and has no effect; only `audience` narrows."


def main() -> int:
    try:
        subject = access_token("alice")
    except Exception as exc:  # a probe reports; it does not raise
        print(f"could not get a token from Keycloak: {exc}", file=sys.stderr)
        print("is the stack up? `make up`", file=sys.stderr)
        return 0

    print("RFC 8707 `resource` against Keycloak — measurement, not assertion\n")
    results: dict[str, dict[str, Any]] = {}
    for label, extra in CASES:
        result = exchange(subject, **extra)
        results[label] = result
        sent = ", ".join(f"{k}={v}" for k, v in extra.items()) or "(nothing)"
        if result["ok"]:
            print(f"  {label}\n    sent: {sent}\n    aud:  {result['aud']}\n")
        else:
            print(f"  {label}\n    sent: {sent}\n    FAILED: {result['detail']}\n")

    print(f"\nVERDICT: {classify(results)}\n")
    print("Full results:")
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
