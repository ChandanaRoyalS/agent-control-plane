"""Does Keycloak accept a Client ID Metadata Document as a `client_id`?

Run against a stack brought up with `make up`:

    uv run python scripts/probe_cimd.py

**This is a measurement, not a test.** It asserts nothing and always exits 0.
Its output decides how task 25 is closed, which is the same order — and for the
same reason — as the RFC 8707 probe in `probe_resource_indicator.py`.

What CIMD is
------------

The Client ID Metadata Document draft
(`draft-ietf-oauth-client-id-metadata-document`) lets a client's `client_id`
*be* an HTTPS URL. Instead of registering a client out of band and configuring
its ID and secret, the client presents the URL, and the authorization server
dereferences it to fetch the client's metadata as JSON. No pre-registration, no
shared secret on disk.

Where it would fit here
-----------------------

This gateway is the token-exchange *client*. Today it proves itself to Keycloak
with `client_id=acp-gateway` and a committed secret (see
`probe_resource_indicator.py` and ADR 0019). CIMD would replace that pair with a
URL Keycloak fetches — dropping the shared secret. That is the only reading of
CIMD that touches code this project has: the inbound reading, where a *calling
agent* asserts a URL identity to the gateway, would have the gateway dereference
an attacker-supplied URL at authentication time, which is a request-forgery
surface aimed at the control plane and a deliberate non-goal. The probe below
therefore measures the gateway-as-client direction only.

Why measure before implementing
-------------------------------

The same rule the RFC 8707 probe was written for. Task 23's brief named RFC
9207, which defends a redirect-flow client and never reaches a resource server;
implementing it literally would have been a citation with no control behind it,
which is worse than none because a reviewer believes it. CIMD is the same shape
of risk in the other direction: writing "supports CIMD" — or writing "Keycloak
does not support CIMD" — without asking the server is an assertion dressed as a
measurement. So: send an exchange with a URL-form `client_id` several ways, and
read what comes back.

What the answers mean
---------------------

**HONOURED** — Keycloak dereferences the URL, mints a token, and the token names
the gateway as the authorized party (`azp`). CIMD works against this server; the
feature is a config change in `identity/exchange.py` and the ADR records how.

**REJECTED** — the exchange that works with the registered `acp-gateway` client
fails when the same request carries a URL `client_id`. Expected, because
Keycloak 26.x has no CIMD support. The ADR records the deviation, keeps the
registered-client exchange, and documents the seam so a future CIMD-capable IdP
is a config change rather than a rewrite.

**INCONCLUSIVE** — even the registered-client baseline failed, so nothing below
is about CIMD. Is the stack up, and is the realm current? `make up`,
`make idp-reset`.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from keycloak_token import access_token, claims, post_form, token_endpoint

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 — a type URI

# The registered exchange client — the task 27/28 baseline. Same values the
# RFC 8707 probe uses, kept here rather than imported so the two probes stay
# independent measurements.
REGISTERED_CLIENT_ID = "acp-gateway"
REGISTERED_CLIENT_SECRET = "dev-only-not-a-secret-either"  # noqa: S105 — a committed fixture

MOCK_A = "acp-upstream-mock-a"

# A URL-form client_id. This does not have to resolve to anything for the probe
# to be informative: what is being measured is whether Keycloak treats a URL as
# a client identifier at all, or rejects it as an unknown client before it would
# ever try to fetch it. A server with no CIMD support answers the same way for a
# reachable URL and an unreachable one — `invalid_client` — which is precisely
# the distinction the probe is here to record.
CIMD_CLIENT_URL = "https://gw.example/acp-gateway/client-metadata.json"


def exchange(subject_token: str, **client_fields: str) -> dict[str, Any]:
    """One token-exchange, returning a flat summary rather than raising.

    `client_fields` carries whatever identifies the client for this case — the
    registered id+secret for the baseline, a URL `client_id` for the CIMD cases.
    """
    form = {
        "grant_type": GRANT_TYPE,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
        "audience": MOCK_A,
        **client_fields,
    }
    try:
        payload = post_form(token_endpoint(), form)
    except RuntimeError as exc:
        # The OAuth error body is the measurement here — `invalid_client`,
        # `invalid_request`, or something else entirely. keycloak_token's
        # post_form already surfaces the body in the message.
        return {"ok": False, "detail": str(exc)[:400]}

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
    (
        "registered client id + secret (the task 28 baseline)",
        {"client_id": REGISTERED_CLIENT_ID, "client_secret": REGISTERED_CLIENT_SECRET},
    ),
    (
        "url client_id alone (CIMD, no secret)",
        {"client_id": CIMD_CLIENT_URL},
    ),
    (
        "url client_id with the registered secret",
        {"client_id": CIMD_CLIENT_URL, "client_secret": REGISTERED_CLIENT_SECRET},
    ),
]


def classify(results: dict[str, dict[str, Any]]) -> str:
    """Read the possible worlds off the results."""
    baseline = results["registered client id + secret (the task 28 baseline)"]
    cimd_alone = results["url client_id alone (CIMD, no secret)"]
    cimd_with_secret = results["url client_id with the registered secret"]

    if not baseline.get("ok"):
        return (
            "INCONCLUSIVE — even the registered-client baseline failed, so nothing "
            "here is about CIMD. Is the stack up and the realm current? "
            "`make up`, `make idp-reset`."
        )
    if cimd_alone.get("ok") or cimd_with_secret.get("ok"):
        working = cimd_alone if cimd_alone.get("ok") else cimd_with_secret
        return (
            "HONOURED — Keycloak accepted a URL as `client_id` and minted a token "
            f"(azp={working.get('azp')}). CIMD works against this server; ADR 0024 "
            "records how the exchange changes."
        )
    return (
        "REJECTED — the exchange that works with the registered client fails when "
        "the same request carries a URL `client_id`. Keycloak has no CIMD support; "
        "the gateway keeps the registered-client exchange and ADR 0024 documents "
        "the seam for a future IdP."
    )


def main() -> int:
    try:
        subject = access_token("alice")
    except Exception as exc:  # a probe reports; it does not raise
        print(f"could not get a token from Keycloak: {exc}", file=sys.stderr)
        print("is the stack up? `make up`", file=sys.stderr)
        return 0

    print("CIMD (url client_id) against Keycloak — measurement, not assertion\n")
    results: dict[str, dict[str, Any]] = {}
    for label, client_fields in CASES:
        result = exchange(subject, **client_fields)
        results[label] = result
        # Show the client_id being tried but never the secret.
        cid = client_fields.get("client_id", "(none)")
        secret = " +secret" if "client_secret" in client_fields else ""
        head = f"  {label}\n    client_id: {cid}{secret}\n"
        if result["ok"]:
            print(f"{head}    aud:  {result['aud']}  azp: {result['azp']}\n")
        else:
            print(f"{head}    FAILED: {result['detail']}\n")

    print(f"\nVERDICT: {classify(results)}\n")
    print("Full results:")
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
