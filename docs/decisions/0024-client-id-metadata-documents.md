# ADR 0024 — Client ID Metadata Documents: measure before claiming

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 25's brief is Client ID Metadata Documents (CIMD,
`draft-ietf-oauth-client-id-metadata-document`): a client whose `client_id`
*is* an HTTPS URL, which the authorization server dereferences to fetch the
client's metadata as JSON. No out-of-band registration, no shared secret on
disk.

This gateway is the token-exchange *client*. Today it proves itself to Keycloak
with `client_id=acp-gateway` and a committed secret (ADR 0019, and the RFC 8707
probe in `scripts/probe_resource_indicator.py`). CIMD would replace that pair
with a URL Keycloak fetches — removing the one long-lived secret the exchange
path still holds. That is the reading of CIMD that touches code this project
has, and the only one this ADR pursues.

The other reading — a *calling agent* presenting a URL `client_id` to the
gateway, which the gateway then dereferences to identify the caller — is a
deliberate non-goal. It would have the control plane make an outbound request to
an attacker-supplied URL at authentication time, which is a server-side
request-forgery primitive pointed at the gateway itself. The whole project
exists to remove that class of thing, not add it. The gateway identifies callers
by validating a bearer token against a trusted issuer registration (ADR 0016);
it does not fetch identity from a URL the caller names.

CIMD is the same shape of risk that ADR 0020 was written for. Task 23's brief
named RFC 9207, which defends a redirect-flow client and never reaches a
resource server; implementing it literally would have been a citation with no
control behind it — worse than none, because a reviewer believes it. Writing
"supports CIMD" without asking the server is that mistake. So is writing
"Keycloak does not support CIMD" without asking: an assertion dressed as a
measurement. So, as with RFC 8707: measure first.

## What Keycloak actually does

`scripts/probe_cimd.py` sends the token-exchange three ways against Keycloak
26.7.1 and reads what comes back. It asserts nothing and exits 0; `make
probe-cimd` re-runs it.

| sent | result |
|---|---|
| registered `client_id=acp-gateway` + secret | token minted, `aud=[acp-upstream-mock-a]`, `azp=acp-gateway`, subject preserved |
| `client_id=https://gw.example/acp-gateway/client-metadata.json` (no secret) | HTTP 401 `invalid_client` |
| same URL `client_id` + the registered secret | HTTP 401 `invalid_client` |

**VERDICT: REJECTED.** The exchange that works with the registered client fails
the moment the same request carries a URL `client_id`. Keycloak 26.7.1 has no
CIMD support.

The baseline row is what makes the other two mean something: the exchange path
is healthy, so the 401s are about the `client_id`, not about a broken stack. And
the third row carries more than the second — the URL is rejected **even when the
registered secret is also sent**, so this is not Keycloak failing to
authenticate a client it half-recognises. It does not treat the URL as a client
identifier at all: the request is refused as `invalid_client` before there is
any question of dereferencing the URL to fetch a metadata document. There is no
CIMD behaviour here to be conformant or non-conformant with; the mechanism is
simply absent.

This is the same outcome shape as ADR 0020's `resource` probe — the server
answers definitively and the decision follows the answer rather than the
citation.

## Decision

**Keep the registered-client exchange. Do not send a URL `client_id` to this
server.** The gateway continues to present `acp-gateway` and its secret in the
token exchange, exactly as tasks 27–31 built and proved.

**Record the seam, do not build a half-adapter.** The client identity used in
the exchange is already a single, named thing in `identity/exchange.py`. A
CIMD-capable authorization server is therefore a configuration change at that
one site — supply a URL `client_id` and omit the secret — not a rewrite. This
ADR is the note that says so, so that a future IdP does not reopen the question
from zero. This mirrors ADR 0021's rule: the good answer is a seam in the right
place, and a half-working adapter for a deployment we cannot test here would
look like support for something that is not supported.

**Inbound CIMD stays out of scope, on purpose.** The reasoning above is the
whole of it: dereferencing a caller-supplied URL to establish the caller's
identity is an SSRF surface on the control plane. If a future phase ever wants
caller-asserted client identities, it arrives with its own threat model and its
own ADR, not as a footnote to this one.

## Consequences

Task 25 closes as a measurement plus this record, which is a legitimate
deliverable (a probe that asserts nothing and exits 0, its answer captured in an
ADR — same status as the RFC 8707 measurement). Phase 2 — identity — is
complete. Nothing in the running gateway changes.

`probe_cimd.py` stays in the tree and `make probe-cimd` stays available, but —
like `probe-resource` — it does **not** stay in CI as a gating step once the
answer is in this ADR. A measurement that can never fail is a step nobody reads.
It is re-run by hand against a new Keycloak version, or a different IdP, when the
question is worth re-asking.

## References

- `draft-ietf-oauth-client-id-metadata-document`
- ADR 0016 — bind every credential to its issuer (why the gateway does not fetch identity from a caller-named URL)
- ADR 0019 — mint a credential per call, and hold none (the exchange client this would change)
- ADR 0020 — check the scope you were granted (the measure-first precedent)
- ADR 0021 — one backend behind a seam (seam-not-half-adapter)
