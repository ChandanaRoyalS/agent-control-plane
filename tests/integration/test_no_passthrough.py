"""The one property everything else in this project rests on, proved rather than assumed.

**The inbound token never reaches an upstream.** Not on the happy path, not on a
retry, not from a cache, not when the exchange fails, not when the upstream has a
static API key instead, not when nobody authenticated at all. If it ever does,
the upstream that receives it can act as the caller everywhere the caller has
access, and this gateway has not reduced the blast radius of an agent — it has
added a hop to it.

Task 27 asserted this once, on one path: a normal `tools/list` through a normal
client. That is the route somebody would think to check. This file is about the
routes nobody thinks to check, and about making the next person's new route fail
the build until they have thought about it.

What makes this different from the existing assertion
-----------------------------------------------------

**The token is real and it arrives the way real tokens arrive.** A signed JWT,
over HTTP, through the actual `AuthenticationMiddleware`. Nothing here calls
`bind_subject_token` — that would be a test binding the token its own way, which
is precisely the loophole a passthrough test must not have.

**The check is "appears nowhere", not "the Authorization header differs".** A
token copied into `X-Forwarded-Authorization`, folded into a query string, or
tucked into `params._meta` alongside the trace context would pass a check that
only reads one header. So every recorded request is scanned whole: the URL, every
header name and value, and the body.

**Three forms of the token are hunted, not one.** The whole string, its payload
segment, and its signature segment. The signature is the unforgeable half — a
leak that forwarded only that is still a leak — and the payload is what a
well-meaning "pass the claims through for auditing" change would send.

**Coverage is asserted, not hoped for.** Two tests at the bottom fail when
somebody adds a method to the `Upstream` protocol without classifying it, or
adds a second module that can read the inbound token. Those are the alarms on
the walls; everything above them is this week's inspection.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import anyio
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from acp.identity import AuthenticationMiddleware, JwksCache, TokenPolicy, TokenValidator
from acp.identity.exchange import ExchangedCredentials, TokenExchanger
from acp.identity.issuers import IssuerRegistration, IssuerRegistry
from acp.observability import RequestContextMiddleware
from acp.upstream.breaker import CircuitBreaker, breaker_policy_for
from acp.upstream.cache import CachingUpstreamClient
from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig
from acp.upstream.factory import build_upstream
from acp.upstream.guard import Bulkhead, GuardedUpstreamClient
from acp.upstream.protocol import Upstream
from acp.upstream.resilient import RetryingUpstreamClient

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

TOKEN_ENDPOINT = "https://idp.example.test/token"
UPSTREAM_AUDIENCE = "acp-upstream-mock-a"
PEER_AUDIENCE = "acp-upstream-mock-b"

MINTED = "minted.credential.for.mock-a"
STATIC_SECRET = "static-api-key-from-the-store"


# ---------------------------------------------------------------------------
# What counts as a leak
# ---------------------------------------------------------------------------


def secrets_of(token: str) -> tuple[str, ...]:
    """Every form of the inbound token that must not appear anywhere outbound.

    Three, because a leak does not have to be tidy:

    - **the whole string**, which is the obvious forward;
    - **the signature segment**, the unforgeable half — a request carrying only
      that is still carrying the thing that makes the token a credential;
    - **the payload segment**, which is what a "pass the caller's claims through
      so the upstream can audit them" change would send, and which is base64 of
      the caller's identity rather than an opaque handle.

    The *header* segment is deliberately not here. It is `{"alg","kid"}`,
    identical for every token this issuer mints, and asserting on it would
    produce a failure that says "leak" when nothing leaked.
    """
    _, payload, signature = token.split(".")
    return (token, payload, signature)


def leaks_in(request: httpx.Request, needles: tuple[str, ...]) -> list[str]:
    """Where a needle appears in a request, described well enough to fix.

    The whole request, not one header. The URL carries a query string; header
    *names* are as capable of carrying a value as header values are; and the
    body is where `params._meta` lives, which is an extension point with a
    documented habit of accumulating whatever anybody finds convenient.
    """
    found: list[str] = []
    haystacks = {
        "url": str(request.url),
        "body": request.content.decode(errors="replace"),
        **{f"header {name}": value for name, value in request.headers.items()},
        "header names": " ".join(request.headers.keys()),
    }
    for where, hay in haystacks.items():
        found.extend(f"{where}: {needle[:24]}…" for needle in needles if needle in hay)
    return found


# ---------------------------------------------------------------------------
# The two servers on the other end
# ---------------------------------------------------------------------------


class Upstreams:
    """Every request that reached an upstream, kept verbatim.

    Verbatim matters. A recorder that stored only the headers it thought were
    interesting would be a recorder that cannot observe the leak it was built to
    catch.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responses: list[int] = []
        self.next_status: list[int] = []
        self.tool_is_error = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.next_status.pop(0) if self.next_status else 200
        self.responses.append(status)
        if status != 200:
            return httpx.Response(status, text="upstream is unwell")
        body = json.loads(request.content)
        if body["method"] == "tools/call":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "content": [{"type": "text", "text": "ok"}],
                        "isError": self.tool_is_error,
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"tools": [{"name": "search", "inputSchema": {"type": "object"}}]},
            },
        )


class AuthorizationServer:
    """A token endpoint that also records, because it is the one destination the
    inbound token is *allowed* to reach — and a test that never checked it
    arrived there would pass just as happily against a gateway that had quietly
    stopped exchanging anything at all."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            return httpx.Response(400, json={"error": "invalid_target"})
        return httpx.Response(200, json={"access_token": MINTED, "expires_in": 300})


# ---------------------------------------------------------------------------
# The stack under test
# ---------------------------------------------------------------------------

STACKS: dict[str, Callable[[UpstreamClient], Upstream]] = {
    # The bare client, which is the only layer that actually builds a request.
    "bare": lambda client: client,
    "guarded": lambda client: GuardedUpstreamClient(
        client,
        CircuitBreaker(client.config.name, breaker_policy_for(client.config)),
        Bulkhead(client.config.name, client.config.max_concurrency),
    ),
    "retrying": RetryingUpstreamClient,
    "caching": CachingUpstreamClient,
    # What production actually runs: caching(retrying(guarded(client))).
    "full": build_upstream,
}
"""Every composition, and each one is here for a reason rather than for symmetry.

A wrapper cannot add a header — none of them touch the request. But a wrapper
*can* change which request is sent, how many times, and whether one is sent at
all, and each of those is a way for a credential to end up attached to a call it
was not minted for. The bare client is included because the layered ones would
happily hide a leak that only occurs when nothing is wrapping.
"""


def upstream_config(
    *,
    audience: str = UPSTREAM_AUDIENCE,
    credential_ref: str = "",
    credential_header: str = "Authorization",
    credential_scheme: str = "Bearer",
) -> UpstreamConfig:
    """Written out field by field rather than splatted from a dict.

    A `**dict` into a pydantic model type-checks as `Any` and turns a rename
    into a runtime surprise, which is a rule this project learned the hard way
    and applies even in tests — especially in tests, since a security test that
    silently constructs the wrong configuration proves nothing about the right
    one.
    """
    return UpstreamConfig(
        name="mock-a",
        url="http://mock-a:9101/mcp",
        audience=audience,
        credential_ref=credential_ref,
        credential_header=credential_header,
        credential_scheme=credential_scheme,
        max_attempts=3,
        # Small but non-zero: the model refuses zero, and a real sleep between
        # attempts would make the retry scenarios the slowest thing in the suite.
        initial_backoff=0.001,
    )


def exchanger_for(server: AuthorizationServer) -> TokenExchanger:
    registry = IssuerRegistry(
        [
            IssuerRegistration(
                policy=TokenPolicy(issuer=ISSUER, audience=AUDIENCE),
                keys=JwksCache("https://idp.example.test/jwks"),
                token_endpoint=TOKEN_ENDPOINT,
            )
        ]
    )
    return TokenExchanger(
        registry,
        client_id="acp-gateway",
        client_secret="dev-only-not-a-secret",
        peer_audiences=(UPSTREAM_AUDIENCE, PEER_AUDIENCE),
        http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
    )


def validator_for(keypair: Keypair) -> TokenValidator:
    def jwks(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.example.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(jwks)),
    )
    return TokenValidator(
        issuers=IssuerRegistry(
            [
                IssuerRegistration(
                    policy=TokenPolicy(issuer=ISSUER, audience=AUDIENCE),
                    keys=keys,
                    token_endpoint=TOKEN_ENDPOINT,
                )
            ]
        )
    )


# ---------------------------------------------------------------------------
# Driving one scenario end to end
# ---------------------------------------------------------------------------


class Recorder(logging.Handler):
    """Every log record emitted while a scenario ran.

    Deliberately not `caplog`. That fixture is function-scoped, which would force
    the sweep to be re-driven once per assertion — roughly a hundred ASGI round
    trips to answer five questions about the same traffic. A handler owned by
    this module lets the sweep be computed once and interrogated repeatedly,
    which is the difference between a security test people run and one they
    start skipping.
    """

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@dataclass
class Traffic:
    """Everything that left the process during one scenario."""

    upstream: Upstreams
    authorization_server: AuthorizationServer
    logs: list[logging.LogRecord] = field(default_factory=list)
    errors: list[BaseException] = field(default_factory=list)

    @property
    def requests(self) -> list[httpx.Request]:
        return self.upstream.requests


@dataclass(frozen=True)
class Scenario:
    """One named path through the gateway, and how to walk it."""

    name: str
    stack: str
    method: str
    """Which `Upstream` protocol method is exercised. Read by the coverage test
    at the bottom, which is the reason it is data rather than a closure."""

    setup: Callable[[Traffic], None] = lambda _traffic: None
    audience: str = UPSTREAM_AUDIENCE
    credential_ref: str = ""
    credential_header: str = "Authorization"
    credential_scheme: str = "Bearer"
    static_secret: str | None = None
    authenticated: bool = True
    requires_auth: bool = True
    """Whether the gateway is configured with a validator at all.

    `authenticated=False, requires_auth=True` is refused at the edge and never
    reaches the handler. `authenticated=False, requires_auth=False` is the
    unauthenticated deployment mode — the handler runs with no principal, which
    is the state the background health prober is permanently in. Both are paths;
    they are different paths, and conflating them would have left the second
    untested while a green test claimed otherwise."""
    exchange: bool = True
    repeats: int = 1


def drive(scenario: Scenario, keypair: Keypair, inbound: str) -> Traffic:
    """Walk one scenario from an HTTP request to whatever the upstream received.

    The middleware binds the token, not this function. That is the whole reason
    the driver goes through an ASGI app rather than calling the client directly:
    a test that binds the inbound token itself is testing a code path that does
    not exist in production, and would keep passing after the real one broke.
    """
    upstreams, authorization_server = Upstreams(), AuthorizationServer()
    traffic = Traffic(upstreams, authorization_server)
    scenario.setup(traffic)

    config = upstream_config(
        audience=scenario.audience,
        credential_ref=scenario.credential_ref,
        credential_header=scenario.credential_header,
        credential_scheme=scenario.credential_scheme,
    )
    exchanger = exchanger_for(authorization_server) if scenario.exchange else None

    async def handler(_request: Request) -> JSONResponse:
        client = UpstreamClient(
            config,
            httpx.AsyncClient(transport=httpx.MockTransport(upstreams)),
            ExchangedCredentials(exchanger) if exchanger is not None else None,
            scenario.static_secret,
        )
        target = STACKS[scenario.stack](client)
        try:
            for _ in range(scenario.repeats):
                await _invoke(target, scenario.method)
        except BaseException as exc:
            traffic.errors.append(exc)
        finally:
            await target.aclose()
        return JSONResponse({"done": True})

    app = Starlette(routes=[Route("/call", handler, methods=["POST"])])
    validator = validator_for(keypair) if scenario.requires_auth else None
    app.add_middleware(AuthenticationMiddleware, validator=validator, resource=None)
    app.add_middleware(RequestContextMiddleware)

    headers = {"authorization": f"Bearer {inbound}"} if scenario.authenticated else {}

    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            await client.post("/call", headers=headers)

    recorder = Recorder()
    root = logging.getLogger()
    previous = root.level
    root.addHandler(recorder)
    root.setLevel(logging.DEBUG)
    try:
        anyio.run(_run)
    finally:
        root.removeHandler(recorder)
        root.setLevel(previous)
    traffic.logs = recorder.records
    if exchanger is not None:
        anyio.run(exchanger.aclose)
    return traffic


async def _invoke(target: Upstream, method: str) -> None:
    if method == "list_tools":
        await target.list_tools()
    elif method == "call_tool":
        await target.call_tool("search", {"query": "retention"})
    elif method == "invalidate":
        await target.invalidate()
    else:  # pragma: no cover — the coverage test below makes this unreachable
        msg = f"no way to drive {method!r}"
        raise AssertionError(msg)


# ---------------------------------------------------------------------------
# The scenarios
# ---------------------------------------------------------------------------


def _upstream_flaps(traffic: Traffic) -> None:
    """One 503 then success, so the retry path sends a *second* request."""
    traffic.upstream.next_status.extend([503])


def _upstream_is_down(traffic: Traffic) -> None:
    traffic.upstream.next_status.extend([503, 503, 503, 503, 503, 503])


def _exchange_is_refused(traffic: Traffic) -> None:
    traffic.authorization_server.fail = True


def _tool_fails(traffic: Traffic) -> None:
    traffic.upstream.tool_is_error = True


SCENARIOS: tuple[Scenario, ...] = (
    # -- the happy paths, one per composition ------------------------------
    *(Scenario(name=f"{stack}:list_tools", stack=stack, method="list_tools") for stack in STACKS),
    *(Scenario(name=f"{stack}:call_tool", stack=stack, method="call_tool") for stack in STACKS),
    *(Scenario(name=f"{stack}:invalidate", stack=stack, method="invalidate") for stack in STACKS),
    # -- the paths where something goes wrong ------------------------------
    Scenario(
        name="a retried call sends a second request",
        stack="full",
        method="list_tools",
        setup=_upstream_flaps,
    ),
    Scenario(
        name="every attempt against a dead upstream",
        stack="full",
        method="call_tool",
        setup=_upstream_is_down,
    ),
    Scenario(
        name="a refused exchange",
        stack="full",
        method="call_tool",
        setup=_exchange_is_refused,
    ),
    Scenario(
        name="a tool that runs and fails",
        stack="full",
        method="call_tool",
        setup=_tool_fails,
    ),
    Scenario(
        name="an open circuit",
        stack="full",
        method="call_tool",
        setup=_upstream_is_down,
        repeats=8,
    ),
    # -- the paths with a different credential, or none --------------------
    Scenario(
        name="a static credential from the store",
        stack="full",
        method="call_tool",
        audience="",
        credential_ref="legacy-key",
        credential_header="X-API-Key",
        credential_scheme="",
        static_secret=STATIC_SECRET,
        exchange=False,
    ),
    Scenario(
        name="an upstream with no audience",
        stack="full",
        method="call_tool",
        audience="",
    ),
    Scenario(
        name="no exchange configured at all",
        stack="full",
        method="call_tool",
        exchange=False,
    ),
    Scenario(
        name="an unauthenticated deployment",
        stack="full",
        method="call_tool",
        authenticated=False,
        requires_auth=False,
    ),
    Scenario(
        name="a caller with no token where one is required",
        stack="full",
        method="call_tool",
        authenticated=False,
    ),
    # -- the path task 30 added --------------------------------------------
    Scenario(
        name="a second call served from the credential cache",
        stack="full",
        method="call_tool",
        repeats=2,
    ),
)


@pytest.fixture(name="inbound", scope="module")
def _inbound(keypair: Keypair) -> str:
    """One token, signed once, used by every scenario in this module.

    Signed once because `claims()` stamps `iat` from the clock: a token minted
    inside the driver and a token minted inside the assertion would be two
    different strings a second apart, and the search for a leak would look in
    the right places for the wrong needle — passing whatever the gateway did.
    """
    return keypair.sign(claims())


@pytest.fixture(name="swept", scope="module")
def _swept(keypair: Keypair, inbound: str) -> list[tuple[Scenario, Traffic]]:
    """Every scenario driven once, for every assertion below to share.

    One pass, several questions. The alternative — each test driving the whole
    matrix itself — was five times the work for identical traffic, and the cost
    of a slow security test is that it gets moved out of the fast suite and then
    out of the habit.
    """
    return [(scenario, drive(scenario, keypair, inbound)) for scenario in SCENARIOS]


def traffic_for(swept: list[tuple[Scenario, Traffic]], name: str) -> Traffic:
    """One scenario's traffic out of the shared sweep, by name.

    `next` with no default on purpose: renaming a scenario and forgetting the
    assertion that reads it should be a `StopIteration` at the point of the
    mistake, not a silently skipped check.
    """
    return next(traffic for scenario, traffic in swept if scenario.name == name)


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def test_no_path_sends_the_inbound_token_to_an_upstream(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """The property the entire security model rests on, over every path at once.

    A failure names the scenario and the exact place the token turned up, because
    "the no-passthrough test failed" is a sentence that starts an afternoon and
    "scenario 'a retried call': header x-forwarded-authorization" ends one.
    """
    needles = secrets_of(inbound)
    found: list[str] = []

    for scenario, traffic in swept:
        for request in traffic.requests:
            found.extend(f"{scenario.name} → {where}" for where in leaks_in(request, needles))

    assert found == [], "the inbound token reached an upstream:\n  " + "\n  ".join(found)


def test_the_sweep_actually_reached_upstreams(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """The test above passes trivially if nothing was ever sent.

    This is the guard against the most embarrassing possible version of a green
    suite: a driver that silently stopped working, an assertion over an empty
    list, and a security property that nobody has checked in months.
    """
    reached = sum(len(traffic.requests) for _, traffic in swept)

    assert reached >= len(STACKS) * 2, f"only {reached} requests left the process"


def test_the_upstream_receives_the_minted_credential_instead(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """Not sending the caller's token is only half of it. A gateway that sent
    *nothing* would pass the test above and would have stopped doing its job —
    so the positive half is asserted in the same sweep."""
    seen: set[str] = set()

    for _, traffic in swept:
        seen.update(
            request.headers["authorization"]
            for request in traffic.requests
            if "authorization" in request.headers
        )

    assert seen == {f"Bearer {MINTED}"}


def test_the_inbound_token_does_reach_the_authorization_server(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """The reason the invariant is about a *destination* and not about the token
    being unreachable. RFC 8693 requires sending it as `subject_token`, to the
    server that issued it. If it went nowhere, no credential could be minted and
    the gateway would be secure in the way an unplugged one is."""
    exchanged = [traffic for _, traffic in swept if traffic.authorization_server.requests]

    assert exchanged, "no scenario exchanged anything"
    bodies = [r.content.decode() for t in exchanged for r in t.authorization_server.requests]
    assert any(inbound in body for body in bodies), "the token never reached its own issuer"


def test_a_static_credential_never_travels_with_the_callers_token(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """Task 29's path, which bypasses exchange entirely and is therefore the one
    where a "well, we have no minted credential, send what we have" fallback
    would be easiest to write and hardest to notice."""
    needles = secrets_of(inbound)
    traffic = traffic_for(swept, "a static credential from the store")

    assert traffic.requests, "the static-credential path sent nothing"
    for request in traffic.requests:
        assert leaks_in(request, needles) == []
        assert request.headers["x-api-key"] == STATIC_SECRET
        assert "authorization" not in request.headers


def test_a_call_with_no_principal_carries_no_credential_rather_than_a_borrowed_one(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """There is no caller, so there is nothing to exchange.

    This is the state the background health prober lives in permanently, and the
    failure worth guarding against is not a leak but a *substitution* — reaching
    for the gateway's own credential, or for the last one it happened to hold,
    because a request path would rather send something than nothing. Sending
    nothing is the correct answer, and ADR 0019 records why the prober's real
    credential is a separate piece of work.
    """
    traffic = traffic_for(swept, "an unauthenticated deployment")

    assert traffic.requests, "the unauthenticated path sent nothing at all"
    assert all("authorization" not in r.headers for r in traffic.requests)
    assert traffic.authorization_server.requests == []


def test_a_caller_with_no_token_is_stopped_before_any_upstream_is_touched(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """The other half, and the stronger result: where a token is required, an
    anonymous request never reaches the handler, so no upstream is contacted and
    no exchange is attempted. Worth its own assertion because "no leak" and
    "no request" are different facts, and a test that accepted either would stop
    noticing if the middleware started letting anonymous calls through."""
    traffic = traffic_for(swept, "a caller with no token where one is required")

    assert traffic.requests == [], "an anonymous caller reached an upstream"
    assert traffic.authorization_server.requests == []


# ---------------------------------------------------------------------------
# Never written down
# ---------------------------------------------------------------------------


def test_no_path_writes_the_inbound_token_to_a_log(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """A token in a log line has left the process as surely as one in a header,
    and it lands somewhere with a longer retention and a wider audience.

    Every record is rendered the way a handler would render it, and every extra
    is stringified, because the leak this catches is `extra={"headers": ...}` —
    a line that looks harmless in source and prints a credential in production.
    """
    needles = secrets_of(inbound)
    found: list[str] = []

    for scenario, traffic in swept:
        for record in traffic.logs:
            rendered = " ".join(
                [record.getMessage(), *(f"{k}={v!r}" for k, v in record.__dict__.items())]
            )
            found.extend(
                f"{scenario.name} → {record.name}: {record.getMessage()}"
                for needle in needles
                if needle in rendered
            )

    assert found == [], "the inbound token was written to a log:\n  " + "\n  ".join(found)


def test_no_path_puts_the_inbound_token_in_an_exception(
    inbound: str, swept: list[tuple[Scenario, Traffic]]
) -> None:
    """Exception messages travel further than logs: into tracebacks, into error
    responses, into issue trackers pasted by whoever hit the bug. Task 27 gave
    `ExchangedToken` a custom `__repr__` for exactly this reason; this asserts
    the property rather than that one implementation of it."""
    needles = secrets_of(inbound)
    found: list[str] = []

    for scenario, traffic in swept:
        for error in traffic.errors:
            text = f"{error!r} {error}"
            found.extend(f"{scenario.name} → {type(error).__name__}" for n in needles if n in text)

    assert found == [], "the inbound token appeared in an exception:\n  " + "\n  ".join(found)


# ---------------------------------------------------------------------------
# The alarms — these fail when somebody adds a path, not when one leaks
# ---------------------------------------------------------------------------

SWEPT_METHODS = frozenset({"list_tools", "call_tool", "invalidate"})
CANNOT_REACH_AN_UPSTREAM = frozenset({"config", "aclose"})
"""`config` is data and `aclose` releases a pool. Neither builds a request, and
both are listed by name so that classifying a *new* method is a deliberate act."""


def test_every_method_on_the_upstream_protocol_is_accounted_for() -> None:
    """The alarm on the wall.

    Add a method to `Upstream` — `read_resource`, `get_prompt`, whatever Phase 3
    needs — and this fails until it is either swept above or declared incapable
    of making a request. Without it, the sweep silently covers less of the
    surface every time the surface grows, which is how a security test decays
    into a formality.

    Read with `dir()` rather than `typing.get_protocol_members` because that
    helper landed in 3.13 and this project supports 3.12.
    """
    declared = frozenset(name for name in dir(Upstream) if not name.startswith("_"))

    assert declared == SWEPT_METHODS | CANNOT_REACH_AN_UPSTREAM


def test_every_stack_composition_is_swept() -> None:
    """The same alarm for the layers. A new wrapper that nobody swept is a new
    place for a request to be built differently."""
    swept = {scenario.stack for scenario in SCENARIOS}

    assert swept == set(STACKS)


def test_exactly_one_module_can_read_the_inbound_token() -> None:
    """The strongest guarantee in this file, and the cheapest.

    Everything above proves that no *current* path leaks. This makes the next
    path fail the build: `current_subject_token` is the only way to obtain the
    inbound token, so the set of source files that call it bounds the set of
    code that could ever leak it. One file is in the set. If a second appears,
    somebody is holding the token somewhere new, and that is a design decision
    that deserves a conversation rather than a merge.

    A source scan rather than a runtime check, because the property is about
    what *could* execute, not about what did.
    """
    src = Path(__file__).resolve().parents[2] / "src" / "acp"
    call = re.compile(r"(?<!def )\bcurrent_subject_token\s*\(")

    readers = {
        path.relative_to(src).as_posix()
        for path in src.rglob("*.py")
        if call.search(path.read_text(encoding="utf-8"))
    }

    assert readers == {"identity/exchange.py"}, (
        f"the inbound token has more than one reader: {sorted(readers)}. "
        f"That is the invariant this whole file exists to protect."
    )


def test_exactly_one_module_can_bind_the_inbound_token() -> None:
    """The other end of the same argument. One writer, at the edge, from the
    `Authorization` header — so there is no second way for a token to enter the
    context and no path where one arrives without having been validated."""
    src = Path(__file__).resolve().parents[2] / "src" / "acp"
    call = re.compile(r"(?<!def )\bbind_subject_token\s*\(")

    writers = {
        path.relative_to(src).as_posix()
        for path in src.rglob("*.py")
        if call.search(path.read_text(encoding="utf-8"))
    }

    assert writers == {"identity/asgi.py"}, f"the inbound token has more than one writer: {writers}"
