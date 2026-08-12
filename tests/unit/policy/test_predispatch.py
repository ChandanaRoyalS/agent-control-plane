"""Header-based pre-dispatch authorization.

Two halves, and the second is the one with teeth. `could_ever_allow` is a
conservative reading of a policy that must never say "no" to a call the real
evaluator would permit — a false refusal here is a legitimate caller broken by
an optimisation that was supposed to be invisible. The middleware is raw ASGI,
so these run without a server, a transport or the MCP SDK.
"""

from __future__ import annotations

import json
from typing import Any

import anyio

from acp.identity.principal import Actor, Principal, bind_principal
from acp.policy.evaluate import evaluate
from acp.policy.predispatch import (
    PreDispatchAuthorizationMiddleware,
    could_ever_allow,
)
from acp.policy.schema import Effect, Policy, Rule
from acp.upstream.envelope import encode_header_value

ISSUER = "https://idp.test"
TOOL = "mock-a__read_document"
AWKWARD = "mock-a__résumé"
"""A tool name the header codec has to encode, because it is not visible ASCII.

Upstream tool names come from servers this gateway does not control, so a name
outside ASCII is an input somebody else chooses, not a hypothetical.
"""


def principal(subject: str = "alice", actor: str | None = None) -> Principal:
    return Principal(
        subject=subject,
        issuer=ISSUER,
        actor=Actor(subject=actor) if actor is not None else None,
    )


# ---------------------------------------------------------------------------
# could_ever_allow — the conservative reading
# ---------------------------------------------------------------------------


def test_an_empty_policy_could_never_allow_anything() -> None:
    assert not could_ever_allow(Policy(rules=()), principal(), TOOL)


def test_a_matching_allow_means_it_could_be_allowed() -> None:
    policy = Policy(rules=(Rule(name="a", effect=Effect.ALLOW, tools=(TOOL,)),))

    assert could_ever_allow(policy, principal(), TOOL)


def test_an_allow_constrained_by_arguments_still_counts() -> None:
    """The trap that makes a naive implementation wrong.

    At header time the arguments are unknown — the body is exactly what has not
    been read. Evaluating with an empty mapping would find this rule *not
    matching* and refuse a call the real check permits, which is a legitimate
    caller broken by the fast path.
    """
    policy = Policy(
        rules=(
            Rule(
                name="public-only",
                effect=Effect.ALLOW,
                tools=(TOOL,),
                args={"doc_id": ("public",)},
            ),
        )
    )

    assert could_ever_allow(policy, principal(), TOOL)
    # And the naive question really would have answered "no":
    assert not evaluate(policy, principal(), TOOL).allowed


def test_an_unconstrained_deny_settles_it() -> None:
    """A deny with no argument constraints matches every call to this tool by
    this principal, so no argument can rescue it."""
    policy = Policy(
        rules=(
            Rule(name="no", effect=Effect.DENY, tools=(TOOL,)),
            Rule(name="yes", effect=Effect.ALLOW, tools=(TOOL,)),
        )
    )

    assert not could_ever_allow(policy, principal(), TOOL)


def test_a_deny_constrained_by_arguments_does_not_settle_it() -> None:
    """It decides only the calls whose arguments match it. The rest fall through
    to later rules, so the walk continues — and finds the allow."""
    policy = Policy(
        rules=(
            Rule(
                name="not-secret",
                effect=Effect.DENY,
                tools=(TOOL,),
                args={"doc_id": ("secret",)},
            ),
            Rule(name="otherwise", effect=Effect.ALLOW, tools=(TOOL,)),
        )
    )

    assert could_ever_allow(policy, principal(), TOOL)


def test_rules_for_other_principals_are_skipped() -> None:
    policy = Policy(rules=(Rule(name="bob-only", effect=Effect.ALLOW, subjects=("bob",)),))

    assert could_ever_allow(policy, principal("bob"), TOOL)
    assert not could_ever_allow(policy, principal("alice"), TOOL)


def test_a_rule_naming_actors_needs_an_actor() -> None:
    policy = Policy(rules=(Rule(name="agents", effect=Effect.ALLOW, actors=("agent-a",)),))

    assert could_ever_allow(policy, principal(actor="agent-a"), TOOL)
    assert not could_ever_allow(policy, principal(), TOOL)


def test_it_never_refuses_what_the_evaluator_would_allow() -> None:
    """The invariant the whole design rests on, asserted directly.

    Every argument mapping a caller could send, against a policy built to make
    the fast path disagree if it is going to. If `could_ever_allow` says no,
    `evaluate` must say no for all of them.
    """
    policy = Policy(
        rules=(
            Rule(name="d1", effect=Effect.DENY, tools=(TOOL,), args={"doc_id": ("secret",)}),
            Rule(name="a1", effect=Effect.ALLOW, tools=(TOOL,), args={"doc_id": ("public",)}),
        )
    )
    mappings: list[dict[str, object]] = [
        {},
        {"doc_id": "public"},
        {"doc_id": "secret"},
        {"doc_id": "other"},
    ]

    if not could_ever_allow(policy, principal(), TOOL):
        for arguments in mappings:
            assert not evaluate(policy, principal(), TOOL, arguments).allowed


# ---------------------------------------------------------------------------
# The middleware
# ---------------------------------------------------------------------------


class Downstream:
    """Records whether the request ever reached the application."""

    def __init__(self) -> None:
        self.called = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def scope_for(method: str | None = "tools/call", name: str | None = TOOL) -> dict[str, Any]:
    headers: list[tuple[bytes, bytes]] = []
    if method is not None:
        headers.append((b"mcp-method", method.encode()))
    if name is not None:
        headers.append((b"mcp-name", name.encode()))
    return {"type": "http", "path": "/mcp", "headers": headers}


def drive(
    middleware: PreDispatchAuthorizationMiddleware, scope: dict[str, Any]
) -> tuple[int, dict[str, Any]]:
    """Run one request through the middleware and read what came back.

    Driven with ``anyio.run`` rather than an ``async def`` test, which is this
    project's convention: the event loop is started and finished inside one
    synchronous call, so nothing depends on which async plugin is configured.
    """
    sent: list[dict[str, Any]] = []

    async def _run() -> None:
        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        async def receive() -> dict[str, Any]:  # pragma: no cover - never awaited
            return {"type": "http.request", "body": b""}

        await middleware(scope, receive, send)

    anyio.run(_run)
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = next((m for m in sent if m["type"] == "http.response.body"), {"body": b"{}"})
    return int(start["status"]), json.loads(body["body"] or b"{}")


ALLOWS = Policy(rules=(Rule(name="ok", effect=Effect.ALLOW, tools=(TOOL,)),))
DENIES = Policy(rules=(Rule(name="no", effect=Effect.DENY, tools=(TOOL,)),))


def test_a_permitted_call_reaches_the_application() -> None:
    bind_principal(principal())
    app = Downstream()

    status, _ = drive(PreDispatchAuthorizationMiddleware(app, policy=ALLOWS), scope_for())

    assert app.called
    assert status == 200


def test_a_call_no_rule_could_permit_is_refused_before_the_body() -> None:
    """The point of the whole exercise: the application never runs, so nothing
    parsed an attacker-controlled body to reach this decision."""
    bind_principal(principal())
    app = Downstream()

    status, body = drive(PreDispatchAuthorizationMiddleware(app, policy=DENIES), scope_for())

    assert not app.called
    assert status == 403
    assert body == {"error": "forbidden"}


def test_the_refusal_names_neither_the_rule_nor_the_tool() -> None:
    """The same undifferentiated refusal `PolicyDeniedError` gives. Telling a
    caller which rule refused it, or that a tool exists but is forbidden, is an
    oracle they can map one request at a time."""
    bind_principal(principal())

    _, body = drive(PreDispatchAuthorizationMiddleware(Downstream(), policy=DENIES), scope_for())

    assert set(body) == {"error"}
    assert TOOL not in json.dumps(body)


def test_with_no_policy_nothing_is_decided_here() -> None:
    bind_principal(principal())
    app = Downstream()

    drive(PreDispatchAuthorizationMiddleware(app, policy=None), scope_for())

    assert app.called


def test_a_loaded_policy_with_no_principal_fails_closed() -> None:
    """Policy set, authentication not, is a misconfiguration — and the same one
    `on_call_tool` refuses rather than permits."""
    bind_principal(None)
    app = Downstream()

    status, _ = drive(PreDispatchAuthorizationMiddleware(app, policy=ALLOWS), scope_for())

    assert not app.called
    assert status == 403


def test_a_method_that_names_nothing_is_not_decided() -> None:
    """`tools/list` carries no subject to authorize. Catalogue filtering handles
    that request, and it needs the body."""
    bind_principal(principal())
    app = Downstream()

    drive(
        PreDispatchAuthorizationMiddleware(app, policy=DENIES),
        scope_for(method="tools/list", name=None),
    )

    assert app.called


def test_a_method_whose_name_is_not_a_tool_is_not_decided() -> None:
    """The bug this test exists to prevent, and it is a false refusal.

    `NAME_BEARING_METHODS` lists three methods, but only `tools/call`'s name is
    a *tool*. `resources/read` carries a URI and `prompts/get` a prompt name;
    checking either against tool-shaped rules finds nothing, hits the deny
    default, and refuses a request the real check would have permitted. The
    first version of `_declared_tool` used the whole mapping and would have done
    exactly that.
    """
    for method, name in (("resources/read", "file:///etc/motd"), ("prompts/get", "summarise")):
        bind_principal(principal())
        app = Downstream()

        drive(
            PreDispatchAuthorizationMiddleware(app, policy=DENIES),
            scope_for(method=method, name=name),
        )

        assert app.called, f"{method} was decided here, and it is not a tool call"


def test_an_encoded_name_is_decoded_before_it_is_matched() -> None:
    """A name outside visible ASCII travels base64-wrapped in the codec's
    sentinel. Matching the wrapper against a policy rule would refuse a call for
    the crime of having an awkward name, so the header is decoded with the same
    codec the outbound client and the mock server use."""
    encoded = encode_header_value(AWKWARD)
    assert encoded != AWKWARD, "the fixture must actually exercise the codec"
    allows_awkward = Policy(rules=(Rule(name="ok", effect=Effect.ALLOW, tools=(AWKWARD,)),))
    bind_principal(principal())
    app = Downstream()

    drive(
        PreDispatchAuthorizationMiddleware(app, policy=allows_awkward),
        scope_for(name=encoded),
    )

    assert app.called


def test_an_encoded_name_is_still_refused_when_no_rule_allows_it() -> None:
    """The other half of the pair, and it is needed.

    Neither test pins the behaviour alone. The one above fails if the header is
    matched raw (the sentinel matches no rule, so a permitted call is refused)
    but passes if the layer simply declines to decide on any encoded name. This
    one fails on that second reading, because declining would let the call
    through. Together they say "decoded", and nothing weaker.
    """
    denies_awkward = Policy(rules=(Rule(name="no", effect=Effect.DENY, tools=(AWKWARD,)),))
    bind_principal(principal())
    app = Downstream()

    status, _ = drive(
        PreDispatchAuthorizationMiddleware(app, policy=denies_awkward),
        scope_for(name=encode_header_value(AWKWARD)),
    )

    assert not app.called
    assert status == 403


def test_a_malformed_sentinel_is_declined_rather_than_decided() -> None:
    """`decode_header_value` answers `None` for a broken wrapper rather than
    handing back the literal string, so there is nothing here to decide on."""
    bind_principal(principal())
    app = Downstream()

    drive(PreDispatchAuthorizationMiddleware(app, policy=DENIES), scope_for(name="=?base64?%%%?="))

    assert app.called


def test_a_repeated_routing_header_is_declined_rather_than_decided() -> None:
    """Two names, and nothing to say which one the body will agree with.
    Declining costs a fast path; guessing risks refusing the call actually
    made."""
    bind_principal(principal())
    app = Downstream()
    scope: dict[str, Any] = {
        "type": "http",
        "path": "/mcp",
        "headers": [
            (b"mcp-method", b"tools/call"),
            (b"mcp-name", TOOL.encode()),
            (b"mcp-name", b"mock-a__something_else"),
        ],
    }

    drive(PreDispatchAuthorizationMiddleware(app, policy=DENIES), scope)

    assert app.called


def test_a_request_with_no_routing_headers_is_not_decided() -> None:
    bind_principal(principal())
    app = Downstream()

    drive(
        PreDispatchAuthorizationMiddleware(app, policy=DENIES),
        scope_for(method=None, name=None),
    )

    assert app.called


def test_a_method_header_with_no_name_is_not_decided() -> None:
    bind_principal(principal())
    app = Downstream()

    drive(PreDispatchAuthorizationMiddleware(app, policy=DENIES), scope_for(name=None))

    assert app.called


def test_an_oversized_header_is_declined_rather_than_decided() -> None:
    """This layer refuses only on a positive proof. A header it will not read is
    not one, so the request goes on to the checks that read the body — which
    refuse it there if it deserves refusing."""
    bind_principal(principal())
    app = Downstream()
    scope = scope_for(name="x" * 2000)

    drive(PreDispatchAuthorizationMiddleware(app, policy=DENIES), scope)

    assert app.called


def test_a_non_ascii_header_is_declined_rather_than_decided() -> None:
    bind_principal(principal())
    app = Downstream()
    scope: dict[str, Any] = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"mcp-method", b"tools/call"), (b"mcp-name", "café".encode())],
    }

    drive(PreDispatchAuthorizationMiddleware(app, policy=DENIES), scope)

    assert app.called


def test_a_lifespan_message_passes_straight_through() -> None:
    app = Downstream()
    middleware = PreDispatchAuthorizationMiddleware(app, policy=DENIES)

    async def _run() -> None:
        async def send(_message: dict[str, Any]) -> None:  # pragma: no cover
            return None

        async def receive() -> dict[str, Any]:  # pragma: no cover
            return {"type": "lifespan.startup"}

        await middleware({"type": "lifespan"}, receive, send)

    anyio.run(_run)

    assert app.called
