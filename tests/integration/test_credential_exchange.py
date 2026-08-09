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
from collections.abc import Sequence
from typing import Any

import anyio
import httpx
import pytest

from acp.exceptions import CredentialExchangeError, CredentialProviderUnavailableError
from acp.identity.cache import CredentialCache
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
        # Long enough that the cache's 30s skew margin is not in play. Tests
        # about expiry set it to something inside the margin, which is the
        # honest way to make a credential stale without moving the clock.
        self.expires_in = 300

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = dict(
            part.split("=", 1) for part in request.content.decode().split("&") if "=" in part
        )
        self.exchanges.append(form)
        if self.fail_with is not None:
            return httpx.Response(self.fail_with, json={"error": "invalid_target"})
        audience = form["audience"]
        minted = MINTED_A if audience.endswith("mock-a") else MINTED_B
        if form["subject_token"] != INBOUND:
            # A real authorization server mints a different credential for a
            # different caller, and a mock that did not would make task 30's
            # central failure invisible: alice's credential served to bob would
            # be the same string either way, and every assertion would pass.
            minted = f"{minted}.for.{form['subject_token']}"
        return httpx.Response(200, json={"access_token": minted, "expires_in": self.expires_in})


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


def principal(subject: str = "alice@example.test") -> Principal:
    return Principal(
        subject=subject,
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


def test_without_a_cache_every_call_mints() -> None:
    """Task 27's behaviour, which is still a supported shape and is what every
    other test in this file runs in — ``cache=None`` is how a test counts
    exchanges without a cache answering half of them.

    This is the test task 27 said would change when caching arrived. It has:
    the assertion that *nothing* is reused became an assertion about the
    configuration in which nothing is reused, and everything below is the
    argument about the key that the change was waiting on.
    """
    server, upstream = AuthorizationServer(), Upstream()

    call(server, upstream)
    call(server, upstream)

    assert len(server.exchanges) == 2


# ---------------------------------------------------------------------------
# Caching, and the one mistake that matters
# ---------------------------------------------------------------------------


def session(
    server: AuthorizationServer,
    upstream: Upstream,
    subjects: Sequence[str],
    *,
    cache: CredentialCache | None = None,
    configs: Sequence[UpstreamConfig] | None = None,
) -> None:
    """Several calls through *one* gateway, which is what makes a cache visible.

    ``call`` builds a fresh exchanger every time, so nothing it does can hit a
    cache — deliberately, since most of this file is about what one call does.
    A cache only exists across calls that share a process, and the failure worth
    testing for only exists across calls that share a process *and* differ in
    who made them. So this driver takes a list of callers.

    ``cache`` is for the one test that wants to read the hit and miss counters
    afterwards; leaving it unset gives a fresh cache per session, which is what
    keeps these tests from leaking credentials into each other.
    """
    targets = list(configs or [upstream_config()])
    shared = cache if cache is not None else CredentialCache()

    async def _run() -> None:
        exchanger = TokenExchanger(
            registry(),
            client_id="acp-gateway",
            client_secret="dev-only-not-a-secret",
            cache=shared,
            http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
        )
        clients = [
            UpstreamClient(
                config,
                httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
                ExchangedCredentials(exchanger),
            )
            for config in targets
        ]
        try:
            for index, subject in enumerate(subjects):
                bind_principal(principal(subject))
                bind_subject_token(subject)
                await clients[index % len(clients)].list_tools()
        finally:
            for client in clients:
                await client.aclose()
            await exchanger.aclose()

    anyio.run(_run)


def test_a_repeat_call_from_the_same_caller_is_served_from_the_cache() -> None:
    """The point of the task, and the least interesting assertion in it."""
    server, upstream = AuthorizationServer(), Upstream()

    session(server, upstream, [INBOUND, INBOUND])

    assert len(server.exchanges) == 1, "the second call went back to the token endpoint"
    assert upstream.calls == 2, "the second call did not reach the upstream at all"


def test_a_second_caller_never_receives_the_first_ones_credential() -> None:
    """The whole reason task 30 needed an argument rather than a dictionary.

    Key the cache on the upstream — the obvious thing, since the credential is
    'the credential for mock-a' — and bob is handed a credential minted with
    alice's identity in its subject. Every functional test still passes. Latency
    improves. The upstream's audit log says alice did it.

    Asserted from the *upstream's* side, because that is the only vantage point
    from which the leak is a fact rather than an inference about internals.
    """
    server, upstream = AuthorizationServer(), Upstream()

    session(server, upstream, ["alice.token", "bob.token"])

    assert len(server.exchanges) == 2, "bob was served alice's credential"
    alice, bob = upstream.authorizations
    assert alice != bob
    assert "alice.token" in str(alice)
    assert "bob.token" in str(bob)


def test_a_second_upstream_never_receives_the_first_ones_credential() -> None:
    """The other half of the key, and the confused-deputy defence surviving the
    cache. One caller, two upstreams: reuse here would hand mock-b a credential
    minted for mock-a, which is the thing task 27 mints per call to prevent."""
    server, upstream = AuthorizationServer(), Upstream()

    session(
        server,
        upstream,
        [INBOUND, INBOUND],
        configs=[
            upstream_config("mock-a", "acp-upstream-mock-a"),
            upstream_config("mock-b", "acp-upstream-mock-b"),
        ],
    )

    assert [e["audience"] for e in server.exchanges] == [
        "acp-upstream-mock-a",
        "acp-upstream-mock-b",
    ]
    assert upstream.authorizations == [f"Bearer {MINTED_A}", f"Bearer {MINTED_B}"]


def test_a_credential_about_to_expire_is_minted_again_rather_than_reused() -> None:
    """A credential that is live when the cache checks it and expired when the
    upstream does fails *after* the side effect may have happened. The margin
    exists so that never happens; this asserts the cache applies it rather than
    comparing timestamps and being right most of the time."""
    server, upstream = AuthorizationServer(), Upstream()
    server.expires_in = 5  # inside the 30s skew margin, so never fresh enough

    session(server, upstream, [INBOUND, INBOUND])

    assert len(server.exchanges) == 2


def test_a_burst_from_one_caller_produces_one_exchange() -> None:
    """Single flight, end to end.

    Without the second cache read inside the lock, every request that queued
    while the first was minting goes on to mint its own — which is the defect
    the JWKS cache shipped with in task 22. Here it is worse than wasted work: a
    burst from one agent becomes a burst of token requests, and an authorization
    server that rate-limits the gateway takes the whole estate down rather than
    one caller.

    Twenty concurrent calls, one exchange. The assertion is a count, because a
    count is the only thing that distinguishes a working single flight from a
    cache that merely returns correct answers.
    """
    server, upstream = AuthorizationServer(), Upstream()
    cache = CredentialCache()

    async def _run() -> None:
        exchanger = TokenExchanger(
            registry(),
            client_id="acp-gateway",
            client_secret="dev-only-not-a-secret",
            cache=cache,
            http=httpx.AsyncClient(transport=httpx.MockTransport(server)),
        )
        client = UpstreamClient(
            upstream_config(),
            httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
            ExchangedCredentials(exchanger),
        )
        bind_principal(principal())
        bind_subject_token(INBOUND)
        try:
            async with anyio.create_task_group() as group:
                for _ in range(20):
                    group.start_soon(client.list_tools)
        finally:
            await client.aclose()
            await exchanger.aclose()

    anyio.run(_run)

    assert len(server.exchanges) == 1, f"{len(server.exchanges)} exchanges for one credential"
    assert upstream.calls == 20
    assert (cache.hits, cache.misses) == (19, 1)


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
