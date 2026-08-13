"""One caller's result must never reach another — task 44, on the real path.

`tests/unit/results/test_cache.py` proves the key distinguishes two callers.
That is a fact about a hash. This is a fact about the gateway: a real signed
token through the real middleware, the real policy and budget path, and an
assertion on what the *second caller receives*.

**The mock upstream returns something different every call**, and that is what
makes this test able to fail at all. A mock that answered identically would make
a leak and a correct miss indistinguishable — every assertion would pass whether
or not the cache was keyed on the principal. Task 30 learned this: its
authorization-server mock returned one credential string per audience, so
alice's credential served to bob would have been the same string and the suite
would have been green through the breach.

So the upstream here answers `result-1`, `result-2`, … and the whole file reads
off that counter. Two callers seeing the same number is the breach; seeing
different numbers is the control working.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette

from acp.gateway import UpstreamRegistry, build_app
from acp.identity import AuthenticationMiddleware
from acp.identity.issuers import IssuerRegistration, IssuerRegistry, single_issuer
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator
from acp.policy import Effect, Policy, Rule
from acp.results import CacheableTools, ResultCache
from acp.upstream import UpstreamClient, UpstreamConfig

from ..tokens import AUDIENCE, ISSUER, Keypair, claims

pytestmark = pytest.mark.integration

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}

ALICE = "alice@example.test"
BOB = "bob@example.test"

# Task 58. A second authorization server, so two tenants can each have an
# "alice" — which is the whole point: within one issuer a subject is unique,
# and across two it is not, and every key in this file was built when there
# was only one.
OTHER_ISSUER = "https://idp.globex.test/realms/acp"
CACHED_TOOL = "mock-a__search"
UNCACHED_TOOL = "mock-a__create_ticket"
POLICY_DENIED = -32040


class CountingUpstream:
    """An upstream whose every answer is distinguishable from every other.

    The counter is the instrument. Without it, "bob was served alice's cached
    result" and "bob's call reached the upstream and got the same answer" are the
    same observation, and the test proves nothing.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.fail_next = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "tools/list":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "tools": [
                            {"name": name, "inputSchema": {"type": "object"}}
                            for name in ("search", "create_ticket")
                        ]
                    },
                },
            )
        self.calls += 1
        is_error = self.fail_next
        self.fail_next = False
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "content": [{"type": "text", "text": f"result-{self.calls}"}],
                    "isError": is_error,
                },
            },
        )


def validator_for(keypair: Keypair) -> TokenValidator:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    return TokenValidator(
        issuers=single_issuer(TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys)
    )


def tenanted_validator(keypair: Keypair) -> TokenValidator:
    """Two registrations, two tenants, one signing key (task 58).

    One key deliberately: the tenant boundary must not depend on the two
    issuers having different keys. If it did, this test would be proving the
    mix-up defence over again rather than proving that the TENANT LABEL is
    what separates the cache entries.
    """

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    def keys() -> JwksCache:
        return JwksCache(
            "https://idp.test/jwks",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        )

    return TokenValidator(
        issuers=IssuerRegistry(
            [
                IssuerRegistration(
                    policy=TokenPolicy(issuer=ISSUER, audience=AUDIENCE),
                    keys=keys(),
                    tenant="acme",
                ),
                IssuerRegistration(
                    policy=TokenPolicy(issuer=OTHER_ISSUER, audience=AUDIENCE),
                    keys=keys(),
                    tenant="globex",
                ),
            ]
        )
    )


def parse(response: httpx.Response) -> dict[str, Any]:
    text = response.text
    if text.lstrip().startswith("{"):
        parsed: dict[str, Any] = response.json()
        return parsed
    for line in text.splitlines():
        if line.startswith("data:"):
            frame: dict[str, Any] = json.loads(line[len("data:") :].strip())
            return frame
    msg = f"could not parse gateway response: {text[:200]!r}"
    raise AssertionError(msg)


def text_of(frame: dict[str, Any]) -> str:
    """What the caller actually received, or the error code if it was refused."""
    if "error" in frame:
        return f"error:{frame['error']['code']}"
    blocks = frame["result"].get("content", [])
    return "\n".join(block.get("text", "") for block in blocks)


def conversation(
    upstream: CountingUpstream,
    keypair: Keypair,
    calls: list[tuple[str, str]],
    *,
    policy: Policy | None = None,
    cacheable: CacheableTools | None = None,
    queries: list[str] | None = None,
    validator: TokenValidator | None = None,
) -> list[str]:
    """Drive several calls through one gateway process, returning what each
    caller received.

    One process, because a cache only exists across calls that share one — and
    the failure worth testing for only exists across calls that share a process
    *and* differ in who made them.

    Each entry is ``(token, tool)``. The arguments are identical throughout
    unless ``queries`` says otherwise, so that the only thing varying between two
    calls is who is making them — which is what makes a leak attributable.
    """
    table = cacheable or CacheableTools(ttls={CACHED_TOOL: 30.0})

    def build_validator() -> TokenValidator:
        """The validator for this conversation.

        A function rather than a value because the untenanted path builds a
        *fresh* validator for the app and again for the middleware, each with
        its own key cache. Collapsing them into one shared instance would
        quietly change what every existing test in this file exercises.
        """
        return validator if validator is not None else validator_for(keypair)

    async def _run() -> list[str]:
        client = UpstreamClient(
            UpstreamConfig(name="mock-a", url="http://mock/mcp"),
            httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        )
        app: Starlette = build_app(
            UpstreamRegistry([client]),
            validator=build_validator(),
            policy=policy,
            cacheable=table,
            results=ResultCache(),
        )
        app.add_middleware(AuthenticationMiddleware, validator=build_validator())

        received: list[str] = []
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(client)
            await stack.enter_async_context(app.router.lifespan_context(app))
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as agent:
                for index, (token, tool) in enumerate(calls):
                    query = queries[index] if queries is not None else "retention"
                    response = await agent.post(
                        "/mcp",
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": tool, "arguments": {"query": query}},
                        },
                        headers={**MCP_HEADERS, "authorization": f"Bearer {token}"},
                    )
                    received.append(text_of(parse(response)))
        return received

    return anyio.run(_run)


# ---------------------------------------------------------------------------
# The property
# ---------------------------------------------------------------------------


def test_a_second_caller_never_receives_the_first_ones_result(keypair: Keypair) -> None:
    """The breach this task exists to prevent, observed where it would happen.

    Key on the tool and the arguments and bob reads alice's records. Nothing
    fails, nothing logs, and the upstream's audit trail records one read — by
    alice. The only artefact of the breach is its absence.

    Two assertions, because either alone can pass while the design is broken:
    the upstream must have been called twice, and the two callers must hold
    different answers.
    """
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))
    bob = keypair.sign(claims(sub=BOB))

    received = conversation(upstream, keypair, [(alice, CACHED_TOOL), (bob, CACHED_TOOL)])

    assert upstream.calls == 2, "bob's call was answered from alice's entry"
    assert received[0] != received[1], f"both callers received {received[0]!r}"


def test_two_agents_acting_for_one_person_do_not_share_an_entry(keypair: Keypair) -> None:
    """Deliberate over-specificity. An upstream may scope by the acting agent —
    a support bot that sees redacted fields, a research agent restricted to
    public records — and collapsing those into one entry serves one agent an
    answer computed for another's entitlements."""
    upstream = CountingUpstream()
    seven = keypair.sign(claims(sub=ALICE, act={"sub": "agent-7"}))
    nine = keypair.sign(claims(sub=ALICE, act={"sub": "agent-9"}))

    received = conversation(upstream, keypair, [(seven, CACHED_TOOL), (nine, CACHED_TOOL)])

    assert upstream.calls == 2
    assert received[0] != received[1]


def test_two_tenants_with_the_same_subject_do_not_share_an_entry(keypair: Keypair) -> None:
    """Task 58's breach, on the real path.

    Two authorization servers, two tenants, and an `alice` in each. Same
    subject string, same actor, same tool, same arguments — everything the key
    held before the tenant joined it. Until task 58 these two calls produced
    one cache entry, and the second alice read the first alice's records.

    Nothing about that failure is observable from inside either tenant: the
    answer is well-formed, the policy allowed the call, and the upstream logged
    one read by "alice", which is true. The counter is the only instrument that
    can see it.
    """
    upstream = CountingUpstream()
    acme_alice = keypair.sign(claims(sub=ALICE))
    globex_alice = keypair.sign(claims(sub=ALICE, iss=OTHER_ISSUER))

    received = conversation(
        upstream,
        keypair,
        [(acme_alice, CACHED_TOOL), (globex_alice, CACHED_TOOL)],
        validator=tenanted_validator(keypair),
    )

    assert upstream.calls == 2, "globex's alice was answered from acme's alice's entry"
    assert received[0] != received[1], f"both tenants received {received[0]!r}"


def test_one_tenants_caller_is_still_served_from_the_cache(keypair: Keypair) -> None:
    """The other direction, so the test above cannot pass by the tenanted
    validator simply breaking caching altogether — which would satisfy every
    isolation assertion in this file and quietly disable the feature."""
    upstream = CountingUpstream()
    acme_alice = keypair.sign(claims(sub=ALICE))

    received = conversation(
        upstream,
        keypair,
        [(acme_alice, CACHED_TOOL), (acme_alice, CACHED_TOOL)],
        validator=tenanted_validator(keypair),
    )

    assert upstream.calls == 1, "the second call went upstream"
    assert received[0] == received[1]


def test_the_same_caller_is_served_from_the_cache(keypair: Keypair) -> None:
    """The point of the task, and the least interesting assertion in it — but
    the one that fails when a key is too *specific*, which is the quiet defect
    that breaks nothing and simply sends every call upstream forever."""
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(upstream, keypair, [(alice, CACHED_TOOL), (alice, CACHED_TOOL)])

    assert upstream.calls == 1, "the second call went upstream"
    assert received[0] == received[1] == "result-1"


# ---------------------------------------------------------------------------
# What is not cached
# ---------------------------------------------------------------------------


def test_the_same_caller_asking_a_different_question_gets_a_different_answer(
    keypair: Keypair,
) -> None:
    """The arguments are part of the key, asserted through the gateway.

    `tests/unit/results/test_cache.py` proves the *hash* changes when the
    arguments change. That is a fact about a hash, and it holds even if the
    gateway never passes the arguments in — `on_call_tool` could hand `key_for`
    an empty dict on every call and every other test in this repository would
    still pass, because every other test asks the same question twice.

    So this one asks two different questions and requires two different answers.
    It is the only assertion that fails when the *wiring* drops the arguments
    rather than the key.

    Added because `scripts/mutate_result_cache.py` removed the arguments from
    the key on its first run and nothing went red. The harness found a hole in
    the suite it was written to check, which is the entire reason for having it.
    """
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(
        upstream,
        keypair,
        [(alice, CACHED_TOOL), (alice, CACHED_TOOL)],
        queries=["retention", "churn"],
    )

    assert upstream.calls == 2, "a different question was answered from the old entry"
    assert received[0] != received[1]


def test_a_tool_not_declared_cacheable_always_reaches_its_upstream(keypair: Keypair) -> None:
    """Opt-in, per tool. `create_ticket` writes, and a cached write is a write
    that silently did not happen."""
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    received = conversation(upstream, keypair, [(alice, UNCACHED_TOOL), (alice, UNCACHED_TOOL)])

    assert upstream.calls == 2
    assert received[0] != received[1]


def test_a_failed_result_is_not_held(keypair: Keypair) -> None:
    """A tool that ran and failed is a fact about one moment. Caching it turns a
    blip into a minute of guaranteed failure for everybody sharing the key."""
    upstream = CountingUpstream()
    upstream.fail_next = True
    alice = keypair.sign(claims(sub=ALICE))

    conversation(upstream, keypair, [(alice, CACHED_TOOL), (alice, CACHED_TOOL)])

    assert upstream.calls == 2, "a failed result was cached"


def test_an_empty_table_caches_nothing(keypair: Keypair) -> None:
    """`tools: {}` means what it says, and is the shape a deployment starts in."""
    upstream = CountingUpstream()
    alice = keypair.sign(claims(sub=ALICE))

    conversation(upstream, keypair, [(alice, CACHED_TOOL)] * 2, cacheable=CacheableTools(ttls={}))

    assert upstream.calls == 2


# ---------------------------------------------------------------------------
# The ordering, which is the whole security argument
# ---------------------------------------------------------------------------


def test_a_denied_caller_is_refused_rather_than_served_from_the_cache(
    keypair: Keypair,
) -> None:
    """ADR 0035's central claim, asserted rather than argued.

    Everywhere else in this codebase caching is outermost, because a hit should
    cost nothing (ADR 0006). Put a *result* cache there and a caller the policy
    would refuse is answered from memory, and the denial never runs.

    So: alice is allowed and populates the entry; bob is denied the tool. Bob
    must receive the policy error, must not receive alice's text, and the
    upstream must not have been called a second time — the last part proving the
    refusal happened before the cache rather than after it.
    """
    upstream = CountingUpstream()
    policy = Policy(
        rules=(
            Rule(
                name="allow-alice-search",
                effect=Effect.ALLOW,
                subjects=(ALICE,),
                tools=(CACHED_TOOL,),
            ),
        )
    )
    alice = keypair.sign(claims(sub=ALICE))
    bob = keypair.sign(claims(sub=BOB))

    received = conversation(
        upstream, keypair, [(alice, CACHED_TOOL), (bob, CACHED_TOOL)], policy=policy
    )

    assert received[0] == "result-1"
    assert received[1] == f"error:{POLICY_DENIED}"
    assert "result-1" not in received[1]
    assert upstream.calls == 1
