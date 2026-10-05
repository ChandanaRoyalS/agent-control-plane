"""The per-request envelope every 2026-07-28 request must carry.

Each request carries its envelope in ``params._meta`` and mirrors method and
subject into routing headers. Servers verify headers match the body (mismatch is
``-32020``), so a proxy cannot authorize one method while another runs. Constants
are declared here, outside the SDK (ADR 0005), and
``tests/integration/test_spec_conformance.py`` checks them against the SDK.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

from acp.upstream.models import PROTOCOL_VERSION

# Envelope keys, namespaced because `_meta` is a shared extension point.

PROTOCOL_VERSION_META_KEY: Final = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_META_KEY: Final = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_META_KEY: Final = "io.modelcontextprotocol/clientInfo"

REQUIRED_META_KEYS: Final = (PROTOCOL_VERSION_META_KEY, CLIENT_CAPABILITIES_META_KEY)
"""Both are required. Client info is a SHOULD, not a MUST."""

# Routing headers

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
"""Method to the params key whose value is mirrored into ``Mcp-Name``."""

# Header value codec

_HEADER_SAFE: Final = re.compile(r"^[\x20-\x7E]*$")
"""Visible ASCII plus space; anything else is base64-encoded."""

_SENTINEL: Final = re.compile(r"^=\?base64\?(?P<payload>.*)\?=$")
"""Wrapper marking a value that had to be encoded to survive the wire."""


def encode_header_value(value: str) -> str:
    """Render a value safe to put in an HTTP header.

    Header-safe values pass through; anything else, including a value that looks
    like the sentinel (an attacker could name a tool so), is base64-encoded in it.
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
        # A malformed sentinel is not a value, or it could slip past a comparison.
        return None


# Building a request


TRACE_CONTEXT_KEYS: Final = ("traceparent", "tracestate", "baggage")
"""W3C trace-context keys, carried in ``_meta`` unprefixed per MCP SEP-414."""


def build_meta(client_name: str, client_version: str) -> dict[str, Any]:
    """The ``params._meta`` envelope for one outbound request.

    Capabilities are declared empty; omitting the key is a protocol error.
    """
    return {
        PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": client_name, "version": client_version},
    }


def routing_headers(method: str, params: Mapping[str, Any] | None = None) -> dict[str, str]:
    """The headers that mirror this request's method and subject.

    ``Mcp-Name`` is sent only when the method has a subject and the body carries it.
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

    ``params`` is always returned, even for argument-free methods. ``trace_context``
    is a W3C carrier, passed in so this module needs no OpenTelemetry import.
    """
    meta = build_meta(client_name, client_version)
    if trace_context:
        # Only the spec-reserved keys; `_meta` is a shared namespace.
        meta.update({k: v for k, v in trace_context.items() if k in TRACE_CONTEXT_KEYS})
    return {**(params or {}), "_meta": meta}
