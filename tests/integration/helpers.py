"""Helpers for driving mock upstreams and the gateway itself in tests.

``asgi_client`` builds an in-process HTTP client against an ASGI app: no real
socket, no real network, no external process. That is the whole payoff of owning
the mock upstreams — the suite never depends on anything outside the repository,
so it is fast, deterministic, and works offline and in CI identically.

**And the second half, which task 55 added after paying for its absence.** These
helpers already knew how to build a valid 2026-07-28 request — envelope in
``params._meta``, routing headers derived from the body — and `test_approvals`
was written without them. It hand-rolled a request that omitted the envelope, so
the SDK served it as an older client, so the version-gated result surface mapped
``tools/call`` to a bare ``CallToolResult``, so an ``input_required`` answer
failed to serialise and came back as ``-32603 Handler returned an invalid
result``. Seven rounds of debugging a gateway that was correct the whole time.

The fix is not another helper somebody has to remember to call. `gateway_client`
returns a client whose transport **completes every request on its way out**: any
JSON-RPC body missing the envelope gains it, and the routing headers are derived
from the body that is actually being sent. A test cannot get this wrong by
omission, because there is nothing for it to omit — it writes the request it
means and the transport makes it a valid one. A test that wants a *deliberately*
malformed request (``test_spec_conformance``) writes the bad envelope or the
wrong header explicitly, and anything already present is left exactly as written.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

import httpx
from starlette.applications import Starlette

from acp.gateway import UpstreamRegistry, build_app
from acp.identity import AuthenticationMiddleware
from acp.identity.issuers import single_issuer
from acp.identity.keys import JwksCache
from acp.identity.validator import TokenPolicy, TokenValidator
from acp.mocks import mock_a, mock_b
from acp.upstream import UpstreamClient, UpstreamConfig
from acp.upstream.envelope import routing_headers, with_envelope

from ..tokens import AUDIENCE, ISSUER, Keypair

MCP_URL = "/mcp"

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}
"""Content negotiation the streamable-HTTP transport requires on every request.

Both are mandatory, and the ``accept`` value must name *both* media types: the
SDK picks its response encoding from it and refuses a request that will not take
what it might send.
"""


@asynccontextmanager
async def asgi_client(app: Starlette) -> AsyncIterator[httpx.AsyncClient]:
    """An httpx client wired directly to an ASGI app via ``ASGITransport``."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://mock") as client:
        yield client


def rpc(
    method: str, params: Mapping[str, object] | None = None, request_id: int = 1
) -> dict[str, object]:
    """Build a JSON-RPC request body.

    ``params`` is a ``Mapping`` rather than a ``dict`` on purpose: ``dict`` is
    invariant in its value type, so a caller holding a ``dict[str, list[str]]``
    could not pass it to a ``dict[str, object]`` parameter. ``Mapping`` is
    covariant in its value type, which is what makes ordinary call sites work.

    Always carries the 2026-07-28 envelope in ``params._meta``, because a
    request without one is not a valid request and a test that builds one is
    testing a shape no server accepts. This helper is the single place that
    knows the envelope, so the tests could not drift from the client even if
    someone wanted them to.
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": with_envelope(params, "acp-tests", "0"),
    }


def headers_for(body: Mapping[str, object]) -> dict[str, str]:
    """The routing headers a server will check this body against.

    Derived from the body rather than passed alongside it, so a test cannot
    accidentally assert agreement between two things it wrote separately.
    """
    method = body.get("method")
    if not isinstance(method, str):
        return {}
    params = body.get("params")
    return routing_headers(method, params if isinstance(params, Mapping) else None)


# ---------------------------------------------------------------------------
# Driving the gateway
# ---------------------------------------------------------------------------


def complete(body: dict[str, Any]) -> dict[str, Any]:
    """Fill in whatever this JSON-RPC body is missing to be a valid request.

    **Additive only.** A body that already carries ``_meta`` keeps the one it
    was written with, wrong or right, because a test asserting how the gateway
    treats a bad envelope must be able to send one. What is filled in is what a
    test *forgot*, and forgetting is the failure this exists to make impossible.
    """
    method = body.get("method")
    if not isinstance(method, str):
        return body
    params = body.get("params")
    params = params if isinstance(params, dict) else {}
    if "_meta" in params:
        return body
    return {**body, "params": with_envelope(params, "acp-tests", "0")}


class EnvelopingTransport(httpx.AsyncBaseTransport):
    """Completes every JSON-RPC request passing through, body and headers alike.

    A transport rather than a function the test calls, because a function is a
    thing a test can forget and a transport is not: the request is finished on
    its way to the wire, after the test has stopped being involved. That is the
    difference between a convention and a guarantee, and this project already
    knows which one it got by writing the convention down.

    Anything that is not a JSON-RPC object — a malformed body, a GET, a probe of
    some other endpoint — passes through untouched. This must not become a layer
    that quietly rewrites requests it does not understand.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raw = await request.aread()
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return await self._inner.handle_async_request(request)
        if not isinstance(body, dict) or "jsonrpc" not in body:
            return await self._inner.handle_async_request(request)

        completed = complete(body)
        headers = httpx.Headers(request.headers)
        for name, value in headers_for(completed).items():
            # Only what the test did not say. A conformance test asserting the
            # gateway's header-mismatch check writes the wrong header on purpose
            # and must keep it.
            headers.setdefault(name, value)
        # Recomputed by httpx from the new content; a stale one is a truncated
        # body and a very confusing failure.
        headers.pop("content-length", None)

        return await self._inner.handle_async_request(
            httpx.Request(
                request.method,
                request.url,
                headers=headers,
                content=json.dumps(completed).encode(),
                extensions=request.extensions,
            )
        )


def parse_rpc(response: httpx.Response) -> dict[str, Any]:
    """The JSON-RPC payload, whether it arrived as JSON or as an SSE frame.

    The transport may answer either depending on how the app was built, and a
    test asserting on a decision should not also be asserting on which encoding
    the SDK chose that day.
    """
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


@asynccontextmanager
async def gateway_client(
    app: Starlette, *, token: str | None = None
) -> AsyncIterator[httpx.AsyncClient]:
    """A client that can send this gateway a request it will accept.

    Starts the ASGI lifespan, which is not optional: the SDK's streamable-HTTP
    app starts its session-manager task group there, and a request sent outside
    it reaches an uninitialised server.

    ``base_url`` is loopback because the SDK's DNS-rebinding guard checks the
    ``Host`` header against ``allowed_hosts``, whose default is loopback.
    """
    async with app.router.lifespan_context(app):
        headers = dict(MCP_HEADERS)
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        transport = EnvelopingTransport(httpx.ASGITransport(app=app))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1", headers=headers
        ) as client:
            yield client


async def post_gateway(
    client: httpx.AsyncClient,
    method: str,
    params: Mapping[str, Any] | None = None,
    request_id: int = 1,
) -> httpx.Response:
    """One JSON-RPC request through ``client``, unparsed.

    The body is written as the test means it — method and params, nothing about
    protocol versions or routing headers. `EnvelopingTransport` supplies the
    rest on the way out.

    Returns the *response*, not a payload, because not every refusal this
    gateway makes is a JSON-RPC one. The pre-dispatch check (ADR 0043) answers
    HTTP 403 with a plain body before anything parses JSON-RPC at all, and a
    helper that could only return a payload would quietly turn that into a dict
    that looks like a JSON-RPC error and is not one.
    """
    return await client.post(
        MCP_URL,
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params or {})},
    )


async def call_gateway(
    client: httpx.AsyncClient,
    method: str,
    params: Mapping[str, Any] | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    """One JSON-RPC request through ``client``, parsed.

    For the calls a test expects to *reach* JSON-RPC. Use `post_gateway` when
    the status code is part of what is being asserted.
    """
    return parse_rpc(await post_gateway(client, method, params, request_id))


# ---------------------------------------------------------------------------
# The gateway under test, assembled the way a deployment assembles it
# ---------------------------------------------------------------------------


def mock_clients() -> list[UpstreamClient]:
    """The two mock upstreams, wired in-process.

    Repeated verbatim in five test files before task 55, which is five places
    for one of them to acquire a mock the others do not have — and a suite whose
    files disagree about what "the estate" is proves less than it appears to.
    """
    return [
        UpstreamClient(
            UpstreamConfig(name="mock-a", url="http://mock/mcp"),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_a.app)),
        ),
        UpstreamClient(
            UpstreamConfig(name="mock-b", url="http://mock/mcp"),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_b.app)),
        ),
    ]


def validator_for(keypair: Keypair) -> TokenValidator:
    """A validator that trusts the suite's throwaway keypair and nothing else.

    The JWKS is served from a `MockTransport` rather than a real endpoint, so
    key fetching is exercised — the cache, the issuer binding, the whole path —
    without a network.
    """

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair.jwks())

    keys = JwksCache(
        "https://idp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    return TokenValidator(
        issuers=single_issuer(TokenPolicy(issuer=ISSUER, audience=AUDIENCE), keys)
    )


@asynccontextmanager
async def authenticated_gateway(
    keypair: Keypair,
    *,
    token: str | None = None,
    clients: list[UpstreamClient] | None = None,
    **kwargs: Any,
) -> AsyncIterator[httpx.AsyncClient]:
    """The whole stack: upstreams entered, auth middleware installed, client ready.

    Nothing binds the principal by hand. A real signed token goes through the
    real `AuthenticationMiddleware`, which binds `current_principal()`, which
    `on_call_tool` reads — because a test that set the principal directly would
    exercise a path the gateway does not have (the lesson of
    `test_no_passthrough`).

    ``**kwargs`` reaches `build_app` untouched, so a test names only the feature
    it is about — ``policy=``, ``approvals=``, ``firewall=`` — and inherits a
    correct everything-else.
    """
    upstreams = mock_clients() if clients is None else clients
    app: Starlette = build_app(
        UpstreamRegistry(upstreams), validator=validator_for(keypair), **kwargs
    )
    app.add_middleware(AuthenticationMiddleware, validator=validator_for(keypair))

    async with contextlib.AsyncExitStack() as stack:
        for client in upstreams:
            await stack.enter_async_context(client)
        yield await stack.enter_async_context(gateway_client(app, token=token))
