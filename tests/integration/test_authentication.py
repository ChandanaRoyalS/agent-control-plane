"""The authentication middleware, driven over HTTP against a real ASGI app.

Real tokens, a real key set served by a real (in-process) HTTP transport, and
real status codes. What is being tested here is not "does the validator work" —
that has its own suite — but the things only visible from outside: which status
code comes back, what the ``WWW-Authenticate`` header says, what the caller is
*not* told, and whether the principal is actually readable by the handler on the
other side.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from acp.identity import (
    AuthenticationMiddleware,
    JwksCache,
    ProtectedResource,
    TokenPolicy,
    TokenValidator,
    metadata_route,
    protected_resource,
    single_issuer,
)
from acp.identity.principal import current_principal
from acp.observability import RequestContextMiddleware, context
from acp.observability.log import ContextFilter, JsonFormatter

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration


async def whoami(_request: Request) -> JSONResponse:
    """Reports the principal the middleware bound, or that there wasn't one.

    Reads it from the context rather than from the request, which is the point:
    nothing between the middleware and here had to pass it along.
    """
    principal = current_principal()
    if principal is None:
        return JSONResponse({"authenticated": False})
    return JSONResponse(
        {
            "authenticated": True,
            "subject": principal.subject,
            "actor": principal.actor.subject if principal.actor else None,
            "label": principal.label,
        }
    )


def build(validator: TokenValidator | None, resource: ProtectedResource | None = None) -> Starlette:
    routes = [Route("/whoami", whoami, methods=["GET"])]
    if resource is not None:
        # Mirrors `build_app`: the same object serves the document and defines
        # the exemption, so a test cannot accidentally check one without the
        # other being true.
        routes.insert(0, metadata_route(resource))
    app = Starlette(routes=routes)
    # Same order as `build_app`: authentication added first, so it runs *inside*
    # the request-context middleware and a rejected request still gets an ID.
    app.add_middleware(AuthenticationMiddleware, validator=validator, resource=resource)
    app.add_middleware(RequestContextMiddleware)
    return app


def validator_for(keypair: Keypair, provider_status: int = 200) -> TokenValidator:
    def handle(_request: httpx.Request) -> httpx.Response:
        if provider_status != 200:
            return httpx.Response(provider_status, text="down")
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    # A registry of one. Cross-issuer isolation is task 23's subject and lives
    # in `tests/unit/identity/test_issuers.py`; what these tests are about is
    # what the *outside* of the gateway sees.
    return TokenValidator(
        issuers=single_issuer(TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys)
    )


def get(
    app: Starlette, headers: dict[str, str] | None = None, path: str = "/whoami"
) -> httpx.Response:
    async def _run() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            return await client.get(path, headers=headers or {})

    response: httpx.Response = anyio.run(_run)
    return response


# ---------------------------------------------------------------------------
# Authenticated
# ---------------------------------------------------------------------------


def test_a_valid_token_reaches_the_handler_as_a_principal(keypair: Keypair) -> None:
    token = keypair.sign(claims())

    body = get(build(validator_for(keypair)), {"authorization": f"Bearer {token}"}).json()

    assert body == {
        "authenticated": True,
        "subject": "alice@example.test",
        "actor": "agent-7",
        "label": "alice@example.test via agent-7",
    }


def test_the_scheme_is_matched_case_insensitively(keypair: Keypair) -> None:
    """RFC 7235 says the scheme is case-insensitive, and real clients send
    `bearer`. Rejecting it would be a compatibility bug wearing a security
    costume."""
    token = keypair.sign(claims())

    assert (
        get(build(validator_for(keypair)), {"authorization": f"bearer {token}"}).status_code == 200
    )


# ---------------------------------------------------------------------------
# Refused
# ---------------------------------------------------------------------------


def test_no_credentials_is_a_challenge_without_an_error_code(keypair: Keypair) -> None:
    """RFC 6750 §3: omit `error` when the request carried no credentials.
    Nothing is wrong with them — there are none — and a client reading
    `invalid_token` would conclude its token needs replacing rather than
    presenting one."""
    response = get(build(validator_for(keypair)))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header",
    [
        "Bearer ",
        "Bearer not-a-jwt",
        "Basic dXNlcjpwYXNz",
        "Bearer " + "x" * 9000,
        "",
    ],
)
def test_anything_that_is_not_a_valid_bearer_token_is_refused(
    keypair: Keypair, header: str
) -> None:
    response = get(build(validator_for(keypair)), {"authorization": header})

    assert response.status_code == 401


def test_an_invalid_token_says_invalid_token_and_nothing_more(keypair: Keypair) -> None:
    """One answer for expired, wrong audience, bad signature and unknown key.
    Distinguishing them hands an attacker a way to probe the configuration one
    request at a time."""
    now = int(time.time())
    tokens = {
        "expired": keypair.sign(claims(iat=now - 3600, exp=now - 1800)),
        "wrong audience": keypair.sign(claims(aud="somewhere-else")),
        "wrong issuer": keypair.sign(claims(iss="https://elsewhere.test")),
    }

    bodies = set()
    for token in tokens.values():
        response = get(build(validator_for(keypair)), {"authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
        bodies.add(response.text)

    assert len(bodies) == 1, "the response distinguishes why the token failed"


def test_the_response_never_echoes_the_token(keypair: Keypair) -> None:
    token = keypair.sign(claims(aud="somewhere-else"))

    response = get(build(validator_for(keypair)), {"authorization": f"Bearer {token}"})

    assert token not in response.text
    assert token not in str(dict(response.headers))


def test_a_broken_identity_provider_is_503_not_401(keypair: Keypair) -> None:
    """Not the caller's fault, and reporting it as though their token were bad
    would send every agent in the fleet off to re-authenticate against an
    identity provider that is already down — a dependency outage becoming a
    login storm."""
    token = keypair.sign(claims())

    response = get(
        build(validator_for(keypair, provider_status=500)),
        {"authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert "www-authenticate" not in response.headers


# ---------------------------------------------------------------------------
# Unauthenticated mode
# ---------------------------------------------------------------------------


def test_with_no_provider_configured_requests_pass_through_anonymously() -> None:
    """How every task before this one behaved. It has to keep working, or the
    gateway could not run at all until Phase 2 finishes."""
    body = get(build(None)).json()

    assert body == {"authenticated": False}


def emitted_lines(app: Starlette, headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Drive a request through the real logging pipeline and return the JSON.

    Through an actual handler carrying `ContextFilter`, not by inspecting a
    captured record afterwards. The filter reads contextvars *at emit time*, in
    the task that logged the line — by the time a test looks at a stored record
    that context is gone, so a test that reached for it later would pass against
    a pipeline wired the wrong way round. Exactly the shape of bug 14.
    """
    lines: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(self.format(record))

    handler = Capture()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(ContextFilter())
    logger = logging.getLogger("acp.observability.middleware")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        get(app, headers)
    finally:
        logger.removeHandler(handler)

    return [json.loads(line) for line in lines]


def test_unauthenticated_mode_is_impossible_to_miss_in_the_logs() -> None:
    """The trade for allowing it at all. Startup warns once, and then *every*
    request carries `principal: anonymous` — so nobody can read a log and fail
    to notice that nothing is being authenticated."""
    entry = next(e for e in emitted_lines(build(None)) if e["event"] == "http.request")

    assert entry["principal"] == "anonymous"


def test_an_authenticated_request_logs_who_it_was_for(keypair: Keypair) -> None:
    """Both halves on every line. An audit trail that records the subject and
    drops the actor cannot answer "which agent did this", which is the question
    asked first when an agent turns out to be compromised."""
    token = keypair.sign(claims())

    entries = emitted_lines(build(validator_for(keypair)), {"authorization": f"Bearer {token}"})
    entry = next(e for e in entries if e["event"] == "http.request")

    assert entry["principal"] == "alice@example.test"
    assert entry["actor"] == "agent-7"
    assert entry["client_id"] == "agent-fleet"
    assert token not in json.dumps(entries), "the bearer token reached the logs"


def test_a_rejected_request_still_has_a_request_id(keypair: Keypair) -> None:
    """Which is why authentication is added to the middleware stack *before* the
    request-context middleware, and therefore runs inside it. A 401 nobody can
    correlate is a 401 nobody can investigate."""
    response = get(build(validator_for(keypair)))

    assert response.status_code == 401
    assert response.headers.get("x-request-id")


# ---------------------------------------------------------------------------
# The invariant the whole phase rests on
# ---------------------------------------------------------------------------


def test_the_inbound_token_is_not_reachable_from_the_principal(keypair: Keypair) -> None:
    """Stated as a test rather than as a comment, before there is any code that
    could violate it: **no inbound token is ever forwarded upstream.**

    Task 25 mints a separate, narrowly scoped credential per upstream. The way
    that guarantee gets quietly broken is somebody stashing the raw token on the
    principal "just in case" and a later layer helpfully passing it along — so
    the principal simply does not carry it, and this asserts as much.
    """
    from acp.identity.principal import Principal  # noqa: PLC0415

    token = keypair.sign(claims())
    principal = anyio.run(lambda: validator_for(keypair).validate(token))

    rendered = repr(principal) + str(principal.as_log_fields()) + str(vars_of(principal))

    assert token not in rendered
    assert not any("token" in field.lower() for field in Principal.__dataclass_fields__)


def vars_of(obj: Any) -> dict[str, Any]:
    return {slot: getattr(obj, slot, None) for slot in getattr(type(obj), "__slots__", ())}


def test_the_context_is_not_left_bound_between_requests(keypair: Keypair) -> None:
    """A principal that outlived its request would be a request executing as
    whoever happened to come before it — the worst possible failure in this
    file."""
    app = build(validator_for(keypair))
    get(app, {"authorization": f"Bearer {keypair.sign(claims())}"})

    context.clear()

    assert get(app).status_code == 401


# ---------------------------------------------------------------------------
# Protected resource metadata — RFC 9728, task 24
# ---------------------------------------------------------------------------

RESOURCE = "https://gw.corp.test/mcp"
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"


def resource_for(*servers: str) -> ProtectedResource:
    return protected_resource(RESOURCE, authorization_servers=servers or (ISSUER,))


def test_the_metadata_document_is_readable_without_a_token(keypair: Keypair) -> None:
    """The one thing this endpoint has to be. It answers "how do I authenticate
    here", so requiring authentication to read it is a loop with no entry — a
    client that could satisfy the 401 would not need the document."""
    app = build(validator_for(keypair), resource_for())

    response = get(app, path=METADATA_PATH)

    assert response.status_code == 200
    assert response.json()["resource"] == RESOURCE
    assert response.json()["authorization_servers"] == [ISSUER]


def test_the_exemption_covers_that_path_and_nothing_else(keypair: Keypair) -> None:
    """Exact string equality against one path, never a prefix test. A
    `startswith` allow-list is a bypass waiting to be found — the guard reads
    "public" and the router reads something else about the same string — and
    exact matching fails closed for every spelling the path is not.
    """
    app = build(validator_for(keypair), resource_for())

    for path in (
        "/whoami",
        METADATA_PATH + "/",
        METADATA_PATH + "/../../whoami",
        METADATA_PATH.upper(),
        "/.well-known/oauth-protected-resource",
    ):
        assert get(app, path=path).status_code == 401, f"{path} was served without a token"


def test_the_challenge_points_at_the_document(keypair: Keypair) -> None:
    """RFC 9728 §5.1. This is what turns a 401 from a refusal into an
    instruction: the client has never heard of this gateway, reads the URL,
    fetches the document and learns where to get a token."""
    response = get(build(validator_for(keypair), resource_for()))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == (
        f'Bearer resource_metadata="https://gw.corp.test{METADATA_PATH}"'
    )


def test_an_invalid_token_gets_both_parameters(keypair: Keypair) -> None:
    """`error` and `resource_metadata` together, comma-separated as RFC 7235
    auth-params are. A client whose token was rejected needs to know both that
    it was rejected and where to get another one."""
    token = keypair.sign(claims(aud="somewhere-else"))

    response = get(
        build(validator_for(keypair), resource_for()), {"authorization": f"Bearer {token}"}
    )

    assert response.headers["www-authenticate"] == (
        f'Bearer error="invalid_token", resource_metadata="https://gw.corp.test{METADATA_PATH}"'
    )


def test_without_a_document_the_challenge_names_no_url(keypair: Keypair) -> None:
    """Unchanged from task 22, and deliberately so. A challenge pointing at a
    URL that answers 404 is worse than one pointing at nothing, because it
    sends the client down a discovery path that ends nowhere."""
    response = get(build(validator_for(keypair)))

    assert response.headers["www-authenticate"] == "Bearer"


def test_reading_the_document_still_produces_a_correlatable_log_line() -> None:
    """An unauthenticated endpoint is the one an attacker probes first, so it
    has to appear in the log with a request ID and an explicit `anonymous`
    principal — not be quietly absent because the middleware returned early."""
    app = build(None, resource_for())

    entries = emitted_lines(app)
    entry = next(e for e in entries if e["event"] == "http.request")

    assert entry["principal"] == "anonymous"
    assert entry["request_id"]


def test_the_document_does_not_leak_what_the_gateway_brokers(keypair: Keypair) -> None:
    """It is public by design — an authorization server's own metadata is too —
    but "public by design" is a licence for exactly the fields RFC 9728 defines.
    Upstream names and tool names belong to the authenticated catalogue, and
    ADR 0010 already put that class of information on a loopback listener.
    """
    body = get(build(validator_for(keypair), resource_for()), path=METADATA_PATH).text

    assert set(json.loads(body)) <= {
        "resource",
        "authorization_servers",
        "bearer_methods_supported",
        "resource_name",
        "scopes_supported",
        "resource_documentation",
    }


def test_the_document_is_cacheable(keypair: Keypair) -> None:
    """Without this a client re-fetches it after every 401, and a 401 is the
    normal state of a client whose token has just expired."""
    response = get(build(validator_for(keypair), resource_for()), path=METADATA_PATH)

    assert "max-age" in response.headers["cache-control"]
