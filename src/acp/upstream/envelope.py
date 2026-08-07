"""The per-request envelope every 2026-07-28 request must carry.

The stateless revision removed the ``initialize`` handshake, so there is nowhere
to negotiate a protocol version once and forget about it. Every request instead
carries its own envelope in ``params._meta``, and mirrors two of those values
into HTTP headers so a proxy, rate limiter or WAF can route and authorize
without deserialising a body.

The headers are not a convenience — a server *verifies* they agree with the
body. That check exists to close a specific attack: a proxy authorizes on the
cheap header, and the server then executes a different method than the one that
was authorized. Making them agree is mandatory, and disagreeing is a distinct
error code (``-32020``) rather than a generic bad request.

**Why this is hand-rolled when the SDK exports the same constants.** ADR 0005
keeps the outbound half free of the SDK, and that still holds — but the reason
this module exists at all is that we previously *invented* an envelope shape,
our mocks agreed with it, and 297 green tests never noticed that no real MCP
server would accept a single one of our requests. So the constants are declared
here, and ``tests/integration/test_spec_conformance.py`` asserts every one of
them against the SDK's own values and runs a real request through the SDK's own
validator. Drift becomes a test failure instead of a production incident.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

from acp.upstream.models import PROTOCOL_VERSION

# ---------------------------------------------------------------------------
# Envelope keys — namespaced, because `_meta` is a shared extension point and
# an unnamespaced `protocolVersion` would collide with anyone else's.
# ---------------------------------------------------------------------------

PROTOCOL_VERSION_META_KEY: Final = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_META_KEY: Final = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_META_KEY: Final = "io.modelcontextprotocol/clientInfo"

REQUIRED_META_KEYS: Final = (PROTOCOL_VERSION_META_KEY, CLIENT_CAPABILITIES_META_KEY)
"""Both are required. Client info is a SHOULD, not a MUST."""

# ---------------------------------------------------------------------------
# Routing headers
# ---------------------------------------------------------------------------

MCP_PROTOCOL_VERSION_HEADER: Final = "Mcp-Protocol-Version"
MCP_METHOD_HEADER: Final = "Mcp-Method"
MCP_NAME_HEADER: Final = "Mcp-Name"

NAME_BEARING_METHODS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "tools/call": "name",
        "prompts/get": "name",
        "resources/read": "uri",
    }
)
"""Method to the params key whose value is mirrored into ``Mcp-Name``.

A single mapping used both to decide which header to send and to know which
body field a server will compare it against, so the two can never disagree by
construction.
"""

# ---------------------------------------------------------------------------
# Header value codec
# ---------------------------------------------------------------------------

_HEADER_SAFE: Final = re.compile(r"^[\x20-\x7E]*$")
"""Visible ASCII plus space — the practical bound on an HTTP field value.

Anything outside it cannot travel in a header at all, and a tool named in a
language that is not English is not an edge case worth losing.
"""

_SENTINEL: Final = re.compile(r"^=\?base64\?(?P<payload>.*)\?=$")
"""Wrapper marking a value that had to be encoded to survive the wire."""


def encode_header_value(value: str) -> str:
    """Render a value safe to put in an HTTP header.

    Header-safe values pass through unchanged, so the common case stays
    readable in a packet capture. Anything else is base64-encoded inside the
    sentinel.

    A value that is header-safe but *looks* like a sentinel is encoded too.
    Otherwise a tool literally named ``=?base64?x?=`` would be decoded by the
    server into something else entirely — and since tool names come from
    upstreams the gateway does not control, that is an input an attacker
    chooses.
    """
    if _HEADER_SAFE.match(value) and not _SENTINEL.match(value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def decode_header_value(value: str | None) -> str | None:
    """Reverse :func:`encode_header_value`. ``None`` passes through."""
    if value is None:
        return None
    match = _SENTINEL.match(value)
    if match is None:
        return value
    try:
        return base64.b64decode(match.group("payload"), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        # A malformed sentinel is not a value — reporting it as one would let a
        # caller smuggle a literal `=?base64?...?=` string past a comparison.
        return None


# ---------------------------------------------------------------------------
# Building a request
# ---------------------------------------------------------------------------


TRACE_CONTEXT_KEYS: Final = ("traceparent", "tracestate", "baggage")
"""W3C trace-context keys, carried in ``_meta`` **unprefixed**.

A documented exception to the namespacing rule every other key here follows —
MCP's SEP-414 states it explicitly, because an implementation that namespaced
these as ``io.modelcontextprotocol/traceparent`` would break traces and log
correlation against every implementation that did not.
"""


def build_meta(client_name: str, client_version: str) -> dict[str, Any]:
    """The ``params._meta`` envelope for one outbound request.

    Capabilities are empty and declared rather than omitted: the gateway is a
    broker, not a feature-rich client, and it advertises nothing it cannot
    honour. Omitting the key is a protocol error; sending an empty object is an
    honest answer.
    """
    return {
        PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": client_name, "version": client_version},
    }


def routing_headers(method: str, params: Mapping[str, Any] | None = None) -> dict[str, str]:
    """The headers that mirror this request's method and subject.

    ``Mcp-Name`` is sent only for the methods that have a subject, and only
    when the body actually carries it — a header claiming a name the body does
    not contain is itself a mismatch.
    """
    headers = {
        MCP_PROTOCOL_VERSION_HEADER: PROTOCOL_VERSION,
        MCP_METHOD_HEADER: method,
    }

    name_key = NAME_BEARING_METHODS.get(method)
    if name_key is not None and params is not None:
        subject = params.get(name_key)
        if isinstance(subject, str):
            headers[MCP_NAME_HEADER] = encode_header_value(subject)

    return headers


def with_envelope(
    params: Mapping[str, Any] | None,
    client_name: str,
    client_version: str,
    trace_context: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Attach the envelope to a request's params.

    ``params`` is always present on the wire now, even for a method that takes
    no arguments, because the envelope lives inside it. ``tools/list`` with no
    params is not a valid 2026-07-28 request.

    ``trace_context`` is a W3C carrier — whatever the propagator produced —
    merged in unprefixed alongside the namespaced envelope keys. Passed in
    rather than fetched here so this module stays free of any OpenTelemetry
    import and remains testable without one, which is the same reason the
    protocol constants are declared locally rather than imported from the SDK.
    """
    meta = build_meta(client_name, client_version)
    if trace_context:
        # Only the keys the spec reserves. A propagator can be configured to
        # emit others, and `_meta` is a shared namespace where an unexpected
        # bare key is somebody else's bug to trip over.
        meta.update({k: v for k, v in trace_context.items() if k in TRACE_CONTEXT_KEYS})
    return {**(params or {}), "_meta": meta}
