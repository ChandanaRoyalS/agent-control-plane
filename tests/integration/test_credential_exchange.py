"""The whole outbound chain: a caller's token in, a different token out.

`test_exchange.py` asserts what the gateway asks the authorization server for.
This asserts what the *upstream* ends up holding, which is the only question
anybody outside this repository actually cares about, and it is asserted by
inspecting the request the upstream received rather than by trusting the layer
that built it.

Two mock transports, deliberately separate: one is the authorization server, one
is the upstream. Keeping them apart is what makes the central assertion possible
— the credential the upstream saw can be compared against the one the caller
presented, and against the one the token endpoint returned, because all three
are visible from here and all three are different strings.

No MCP SDK, no containers, no sockets. This runs in the same second as the unit
tests, which is the only reason it can assert on the thing that matters on every
change rather than once per CI run.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import CredentialExchangeError, CredentialProviderUnavailableError
from acp.identity.exchange import ExchangedCredentials, TokenExchanger
from acp.identity.issuers import IssuerRegistration, IssuerRegistry
from acp.identity.keys import JwksCache
from acp.identity.principal import Principal, bind_principal, bind_subject_token
from acp.identity.validator import TokenPolicy
from acp.upstream.breaker import BreakerState, CircuitBreaker, breaker_policy_for
from acp.upstream.client import UpstreamClient
from acp.upstream.config import UpstreamConfig
from acp.upstream.guard import Bulkhead, GuardedUpstreamClient

pytestmark = pytest.mark.integration

ISSUER = "https://idp.corp.test/realms/acp"
TOKEN_ENDPOINT = "https://idp.corp.test/token"

INBOUND = "the.caller.token"
"""What the agent presented to the gateway. Must never leave the process."""

MINTED_A = "credential.for.mock-a"
MINTED_B = "credential.for.mock-b"


class AuthorizationServer:
    """A token endpoint that mints a different credential per audience."""

    def __init__(self) -> None:
        self.exchanges: list[dict[str, str]] = []
        self.fail_with: int | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = dict(
            part.split("=", 1) for part in request.content.decode().split("&") if "=" in part
        )
        self.exchanges.append(form)
        if self.fail_with is not None:
            return httpx.Response(self.fail_with, json={"error": "invalid_target"})
        audience = form["audience"]
        minted = MINTED_A if audience.endswith("mock-a") else MINTED_B
        return httpx.Response(200, json={"access_token": minted, "expires_in": 300})


class Upstream:
    """An MCP server that records the credential it was handed."""

    def __init__(self) -> None:
        self.authorizations: list[str | None] = []
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.authorizations.append(request.headers.get("authorization"))
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}},
        )


def registry() -> IssuerRegistry:
    return IssuerRegistry(
        [
            IssuerRegistration(
                policy=TokenPolicy(issuer=ISSUER, audience="gw"),
                keys=JwksCache("https://idp.corp.test/keys"),
                token_endpoint=TOKEN_ENDPOINT,
            )
        ]
    )


def upstream_config(name: str = "mock-a", audience: str = "acp-upstream-mock-a") -> UpstreamConfig:
    return UpstreamConfig(name=name, url=f"http://{name}:9101/mcp", audience=audience)


def principal() -> Principal:
    return Principal(
        subject="alice@example.test",
        issuer=ISSUER,
        actor=None,
        client_id="acp-agent",
        scopes=frozenset(),
        expires_at=None,
        delegation_chain=(),
    )


def call(
    server: AuthorizationServer,
    upstream: Upstream,
    *,
    config: UpstreamConfig | None = None,
    authenticated: bool = True,
    guarded: bool = False,
) -> Any:
    """Drive one `tools/list` through the real client, with both fakes attached."""

    async def _run() -> Any:
        exchanger = TokenExchanger(
            registry(),
            client_id="acp-gateway",
            client_secret="dev-only-not-a-secret",
            http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
        )
        client = UpstreamClient(
            config or upstream_config(),
            httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
            ExchangedCredentials(exchanger),
        )
        target: Any = client
        if guarded:
            target = GuardedUpstreamClient(
                client,
                CircuitBreaker(client.config.name, breaker_policy_for(client.config)),
                Bulkhead(client.config.name, client.config.max_concurrency),
            )
        # Bound here rather than by middleware, because what is being tested is
        # what the outbound half does with a bound principal — not how it got
        # bound. `test_authentication.py` owns that half.
        bind_principal(principal() if authenticated else None)
        bind_subject_token(INBOUND if authenticated else None)
        try:
            return await target.list_tools(), target
        finally:
            await client.aclose()
            await exchanger.aclose()

    return anyio.run(_run)


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def test_the_upstream_never_receives_the_inbound_token() -> None:
    """The property the entire security model rests on, asserted rather than
    claimed.

    Task 31 makes this exhaustive across every path. This is the first version
    of it, on the path that now deliberately attaches a credential — which is
    the one where getting it wrong would look like a feature working.
    """
    server, upstream = AuthorizationServer(), Upstream()

    call(server, upstream)

    assert upstream.authorizations == [f"Bearer {MINTED_A}"]
    assert INBOUND not in (upstream.authorizations[0] or "")


def test_the_inbound_token_does_reach_the_authorization_server() -> None:
    """The other half, and the reason the invariant is about a *destination*
    rather than about the token being unreachable. It has to go somewhere: the
    server that issued it, as RFC 8693's `subject_token`."""
    server, upstream = AuthorizationServer(), Upstream()

    call(server, upstream)

    assert server.exchanges[0]["subject_token"] == INBOUND


def test_each_upstream_gets_a_credential_minted_for_it_alone() -> None:
    """The confused-deputy defence, end to end. A credential for mock-a is not a
    credential for mock-b, so an upstream that is compromised or merely curious
    cannot replay what it was given against its neighbour."""
    server, mock_a, mock_b = AuthorizationServer(), Upstream(), Upstream()

    call(server, mock_a, config=upstream_config("mock-a", "acp-upstream-mock-a"))
    call(server, mock_b, config=upstream_config("mock-b", "acp-upstream-mock-b"))

    assert mock_a.authorizations == [f"Bearer {MINTED_A}"]
    assert mock_b.authorizations == [f"Bearer {MINTED_B}"]
    assert [e["audience"] for e in server.exchanges] == [
        "acp-upstream-mock-a",
        "acp-upstream-mock-b",
    ]


def test_a_credential_is_minted_per_call_and_not_reused() -> None:
    """Nothing is cached yet, which is task 30's subject. Asserted now so that
    when caching arrives, the test that changes is this one — deliberately,
    with the cache key argued over — rather than a behaviour nobody noticed."""
    server, upstream = AuthorizationServer(), Upstream()

    call(server, upstream)
    call(server, upstream)

    assert len(server.exchanges) == 2


# ---------------------------------------------------------------------------
# When there is nothing to exchange
# ---------------------------------------------------------------------------


def test_an_upstream_with_no_audience_is_called_without_a_credential() -> None:
    """Because nobody said what a credential for it would be *for*, and guessing
    is worse than sending none. Startup refuses this combination outright — see
    `check_upstream_audiences` — so this is the belt to that braces."""
    server, upstream = AuthorizationServer(), Upstream()

    call(server, upstream, config=upstream_config(audience=""))

    assert upstream.authorizations == [None]
    assert server.exchanges == [], "no exchange should have been attempted"


def test_a_call_with_no_principal_carries_no_credential() -> None:
    """The background health prober, which has no caller because no user asked
    for it. A known and scoped gap: the correct answer is a client-credentials
    grant for the gateway's own account, which belongs with task 30."""
    server, upstream = AuthorizationServer(), Upstream()

    call(server, upstream, authenticated=False)

    assert upstream.authorizations == [None]
    assert server.exchanges == []


# ---------------------------------------------------------------------------
# When the exchange fails
# ---------------------------------------------------------------------------


def test_a_refused_exchange_stops_the_call_before_the_upstream_is_touched() -> None:
    """The two alternatives are worse than failing: calling the upstream
    uncredentialed is a gateway that has quietly stopped enforcing the thing it
    exists for, and forwarding the caller's own token is the passthrough this
    phase exists to prevent."""
    server, upstream = AuthorizationServer(), Upstream()
    server.fail_with = 400

    with pytest.raises(CredentialExchangeError):
        call(server, upstream)

    assert upstream.calls == 0, "the upstream was contacted despite having no credential"


def test_a_broken_authorization_server_is_reported_as_recoverable() -> None:
    server, upstream = AuthorizationServer(), Upstream()
    server.fail_with = 503

    with pytest.raises(CredentialProviderUnavailableError) as caught:
        call(server, upstream)

    assert caught.value.recoverable is True
    assert upstream.calls == 0


def test_an_identity_outage_does_not_open_the_upstream_circuit() -> None:
    """The upstream has done nothing wrong and has not been contacted.

    This one found a real bug rather than confirming a design. The breaker's
    predicate counted anything the taxonomy marks ``recoverable`` — which an
    unreachable authorization server correctly is — so one identity outage would
    have opened *every* upstream's circuit at once, withdrawn the whole estate's
    tools from every agent's catalogue, and blamed five servers that were
    answering perfectly.

    Driven through a single long-lived breaker rather than a fresh one per call,
    because the assertion is about accumulation: enough failures to trip it twice
    over, and it must still be closed.
    """
    server, upstream = AuthorizationServer(), Upstream()
    server.fail_with = 503
    config = upstream_config()

    async def _run() -> Any:
        exchanger = TokenExchanger(
            registry(),
            client_id="acp-gateway",
            client_secret="dev-only-not-a-secret",
            http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
        )
        client = UpstreamClient(
            config,
            httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
            ExchangedCredentials(exchanger),
        )
        breaker = CircuitBreaker(config.name, breaker_policy_for(config))
        guard = GuardedUpstreamClient(client, breaker, Bulkhead(config.name, 10))
        bind_principal(principal())
        bind_subject_token(INBOUND)
        try:
            for _ in range(config.failure_threshold * 2):
                with pytest.raises(CredentialProviderUnavailableError):
                    await guard.list_tools()
            return breaker.state
        finally:
            await client.aclose()
            await exchanger.aclose()

    state = anyio.run(_run)

    assert state is BreakerState.CLOSED, "an identity outage opened an upstream's circuit"
    assert upstream.calls == 0
