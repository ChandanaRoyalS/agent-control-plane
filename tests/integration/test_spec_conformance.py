"""Conformance: what the gateway sends, checked against the SDK's own validator.

This file exists because of a bug that 297 passing tests did not catch. The
outbound client sent a `_meta` envelope of its own invention; the mock upstreams
accepted it, because we wrote both sides; and every test was green while no real
MCP server would have accepted a single request the gateway made. It surfaced
the first time the gateway was pointed at its own inbound half, which is built
on the SDK.

The lesson is narrow and worth stating: **a mock that agrees with your client
proves only that you wrote both.** Testing a protocol implementation against
your own idea of the protocol is not testing it at all.

So this module treats the SDK as the authority rather than as a peer. It imports
the spec's constants and its `classify_inbound_request` ladder — both pure, with
no transport or server coupling, which is why using them here does not disturb
ADR 0005's hand-rolled outbound client — and runs requests the real client
actually produced through the real validator. If the two ever drift, this fails
in CI rather than in production against someone else's server.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
import httpx
import pytest
from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    InboundLadderRejection,
    InboundModernRoute,
    classify_inbound_request,
)
from mcp.shared.inbound import (
    NAME_BEARING_METHODS as SDK_NAME_BEARING_METHODS,
)
from mcp.shared.inbound import (
    decode_header_value as sdk_decode,
)
from mcp.shared.inbound import (
    encode_header_value as sdk_encode,
)
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from acp.mocks import mock_a
from acp.mocks.server import validate_envelope
from acp.upstream import UpstreamClient, UpstreamConfig
from acp.upstream import envelope as acp
from acp.upstream.models import PROTOCOL_VERSION
from tests.integration.helpers import rpc

pytestmark = pytest.mark.integration


def sent(
    call: Any, response: httpx.Response | None = None
) -> tuple[dict[str, Any], dict[str, str]]:
    """Capture the body and headers one real client call puts on the wire.

    Deliberately captures from `UpstreamClient` rather than rebuilding a request
    by hand. A hand-built request tests the test.
    """
    bodies: list[dict[str, Any]] = []
    headers: list[dict[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        # Lowercased: the SDK's ladder indexes a plain mapping by canonical
        # lowercase name, and httpx.Headers' case-insensitivity would hide a
        # real mismatch here.
        headers.append({k.lower(): v for k, v in request.headers.items()})
        return response or httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        )

    async def _run() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with UpstreamClient(UpstreamConfig(name="mock-a", url="http://mock/mcp"), http) as c:
            await call(c)

    anyio.run(_run)
    return bodies[0], headers[0]


def call_result() -> httpx.Response:
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": False}}
    )


# ---------------------------------------------------------------------------
# Our constants are the spec's constants
# ---------------------------------------------------------------------------


def test_the_envelope_keys_match_the_specs() -> None:
    """Declared locally so the outbound half stays SDK-free (ADR 0005), pinned
    here so "declared locally" cannot quietly become "made up"."""
    assert acp.PROTOCOL_VERSION_META_KEY == PROTOCOL_VERSION_META_KEY
    assert acp.CLIENT_CAPABILITIES_META_KEY == CLIENT_CAPABILITIES_META_KEY
    assert acp.CLIENT_INFO_META_KEY == CLIENT_INFO_META_KEY


def test_the_routing_header_names_match_the_specs() -> None:
    assert acp.MCP_PROTOCOL_VERSION_HEADER.lower() == MCP_PROTOCOL_VERSION_HEADER
    assert acp.MCP_METHOD_HEADER.lower() == MCP_METHOD_HEADER
    assert acp.MCP_NAME_HEADER.lower() == MCP_NAME_HEADER


def test_the_name_bearing_methods_match_the_specs() -> None:
    """Get this wrong in the omitting direction and `tools/call` is rejected;
    get it wrong the other way and a header is sent for a method that has no
    subject to name."""
    assert dict(acp.NAME_BEARING_METHODS) == dict(SDK_NAME_BEARING_METHODS)


def test_the_protocol_version_is_one_the_sdk_serves() -> None:
    assert PROTOCOL_VERSION in MODERN_PROTOCOL_VERSIONS


# ---------------------------------------------------------------------------
# Our header codec is the spec's codec
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("search", id="plain"),
        pytest.param("read_document", id="underscore"),
        pytest.param("", id="empty"),
        pytest.param("recherche-naïve", id="non-ascii"),
        pytest.param("検索", id="cjk"),
        pytest.param("with space", id="space-is-header-safe"),
    ],
)
def test_our_encoding_is_byte_identical_to_the_specs(value: str) -> None:
    """Byte-identical, not merely round-trippable: the server compares the
    header it received against the body, so a different-but-valid encoding of
    the same string still fails the comparison."""
    assert acp.encode_header_value(value) == sdk_encode(value)


@pytest.mark.parametrize("value", ["search", "recherche-naïve", "=?base64?xxx?="])
def test_the_spec_can_decode_what_we_encode(value: str) -> None:
    """The property that has to hold even where the two encoders might differ:
    whatever we put on the wire, the server reads back the value we meant.

    The third case is a tool name that *looks* like the codec's own sentinel.
    Tool names come from upstreams the gateway does not control, so that is an
    input someone else chooses.
    """
    assert sdk_decode(acp.encode_header_value(value)) == value


def test_we_can_decode_what_the_spec_encodes() -> None:
    assert acp.decode_header_value(sdk_encode("recherche-naïve")) == "recherche-naïve"


# ---------------------------------------------------------------------------
# Real requests, through the real validator
# ---------------------------------------------------------------------------


def accepted(body: dict[str, Any], headers: dict[str, str]) -> InboundModernRoute:
    result = classify_inbound_request(body, headers=headers)
    assert isinstance(result, InboundModernRoute), (
        f"a real MCP server would reject this request: {getattr(result, 'message', result)!r}"
    )
    return result


def test_a_tools_list_request_passes_the_specs_ladder() -> None:
    """The one that would have caught the original bug."""
    body, headers = sent(lambda c: c.list_tools())

    route = accepted(body, headers)

    assert route.protocol_version == PROTOCOL_VERSION


def test_a_tools_call_request_passes_the_specs_ladder() -> None:
    body, headers = sent(lambda c: c.call_tool("search", {"q": "x"}), call_result())

    accepted(body, headers)


def test_a_tool_call_with_an_unheaderable_name_passes_too() -> None:
    """The case that fails silently if the codec is skipped: the raw name is not
    a legal header value, so the comparison the server makes cannot succeed."""
    body, headers = sent(lambda c: c.call_tool("recherche-naïve", {}), call_result())

    accepted(body, headers)


def test_the_client_advertises_who_it_is() -> None:
    """Optional in the spec, and worth sending: an upstream operator reading
    their own logs should be able to tell which client is calling them."""
    body, headers = sent(lambda c: c.list_tools())

    info = accepted(body, headers).client_info

    assert info is not None, "client info is a SHOULD, and worth sending"
    assert info["name"] == "agent-control-plane"
    assert info["version"] == body["params"]["_meta"][CLIENT_INFO_META_KEY]["version"]


# ---------------------------------------------------------------------------
# Our mocks reject what the spec rejects
# ---------------------------------------------------------------------------


def bad_requests() -> list[tuple[str, dict[str, Any], dict[str, str]]]:
    """Requests a real server refuses, each breaking exactly one rule."""
    good = rpc("tools/list")
    good_headers = {
        MCP_PROTOCOL_VERSION_HEADER: PROTOCOL_VERSION,
        MCP_METHOD_HEADER: "tools/list",
    }
    no_meta = {**good, "params": {}}
    partial_meta = {
        **good,
        "params": {"_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION}},
    }
    legacy_shape = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "_meta": {"protocolVersion": PROTOCOL_VERSION},
    }
    return [
        ("no envelope at all", no_meta, good_headers),
        ("envelope missing client capabilities", partial_meta, good_headers),
        ("the shape this project used to send", legacy_shape, good_headers),
        ("method header disagrees with the body", good, {**good_headers, MCP_METHOD_HEADER: "x"}),
        ("version header absent", good, {MCP_METHOD_HEADER: "tools/list"}),
    ]


@pytest.mark.parametrize(
    ("label", "body", "headers"), bad_requests(), ids=[case[0] for case in bad_requests()]
)
def test_the_spec_rejects_each_bad_request(
    label: str, body: dict[str, Any], headers: dict[str, str]
) -> None:
    """Establishes that each case really is invalid, before asking whether our
    mocks agree. Without this the next test could pass by rejecting things that
    are actually fine."""
    assert isinstance(classify_inbound_request(body, headers=headers), InboundLadderRejection), (
        f"expected {label!r} to be rejected"
    )


@pytest.mark.parametrize(
    ("label", "body", "headers"), bad_requests(), ids=[case[0] for case in bad_requests()]
)
def test_our_mocks_reject_each_bad_request(
    label: str, body: dict[str, Any], headers: dict[str, str]
) -> None:
    """The half that closes the loop.

    Mocks that accept requests a real server refuses are why the original bug
    lived through 297 green tests. `legacy_shape` is that exact bug: it is
    rejected here now, so it cannot come back unnoticed.
    """

    async def _run() -> httpx.Response:
        transport = httpx.ASGITransport(app=mock_a.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://mock") as client:
            return await client.post("/mcp", json=body, headers=headers)

    payload = anyio.run(_run).json()

    assert "error" in payload, f"the mock accepted {label!r}, which a real server refuses"


def test_the_mock_validator_accepts_what_the_client_sends() -> None:
    """Both directions of the same claim, in one place: what the client
    produces is what the mocks accept *and* what the spec accepts."""
    body, headers = sent(lambda c: c.call_tool("search", {"q": "x"}), call_result())
    from acp.mocks.jsonrpc import JsonRpcRequest  # noqa: PLC0415

    assert validate_envelope(JsonRpcRequest.model_validate(body), headers) is None
    accepted(body, headers)
