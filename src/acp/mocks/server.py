"""Factory for a mock MCP upstream as a Starlette app; protocol and chaos handling live here.

Concrete servers (``mock_a.py``, ``mock_b.py``) are just a name and a list of ``MockTool``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from acp.mocks.chaos import (
    CHAOS_MODE_HEADER,
    CHAOS_PARAM_HEADER,
    CHAOS_SIMULATED_ERROR,
    DEFAULT_HANG_SECONDS,
    DEFAULT_OVERSIZED_BYTES,
    ChaosMode,
    Disconnected,
    maybe_hang,
    oversized_text,
    resolve_mode,
    resolve_param,
)
from acp.mocks.drift import apply_drift
from acp.mocks.jsonrpc import (
    HEADER_MISMATCH,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    CallToolResult,
    JsonRpcRequest,
    JsonRpcResponse,
    TextContent,
    ToolDefinition,
    call_tool_result,
    error_response,
    tool_definitions_result,
)
from acp.upstream.envelope import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    NAME_BEARING_METHODS,
    REQUIRED_META_KEYS,
    decode_header_value,
)

CATALOGUE_TTL_MS = 60_000
"""The `tools/list` TTL these mocks advertise, so caching is observable in a demo."""

ToolHandler = Callable[[dict[str, Any]], CallToolResult]
"""A deterministic, synchronous function from tool arguments to a result."""


@dataclass(frozen=True, slots=True)
class MockTool:
    """One tool exposed by a mock upstream."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name=self.name, description=self.description, input_schema=self.input_schema
        )


def _json_response(payload: JsonRpcResponse) -> JSONResponse:
    return JSONResponse(payload.model_dump(mode="json", exclude_none=True))


async def _disconnect_stream() -> Any:  # AsyncIterator[bytes], typed loosely for Starlette
    """Yield a partial chunk then raise, after headers are sent, simulating a mid-body drop."""
    yield b'{"jsonrpc": "2.0", "id": 1, "result": {"chaos": "disconnect'
    raise Disconnected


def _apply_oversized(result: dict[str, Any], byte_count: int) -> dict[str, Any]:
    """Inflate any result by adding a filler key."""
    return {**result, "_chaos_filler": oversized_text(byte_count)}


def unverified_claims(token: str) -> dict[str, Any]:
    """A JWT's payload, decoded but *not* verified; ``{}`` if undecodable.

    Test-only (not in the production image, ADR 0014). Shows which credential arrived
    (`sub`, `aud`, `azp`), proving it is the exchanged token, not the caller's.
    """
    try:
        segment = token.split(".")[1]
        payload = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        decoded: dict[str, Any] = json.loads(payload)
    except (IndexError, ValueError, binascii.Error):
        return {}
    return decoded


class SeenCredential:
    """The credential the last ``tools/call`` carried, for out-of-process tests.

    Ignores health-probe ``tools/list`` requests, which would race the test. Stores claims and
    a fingerprint, never the token itself.
    """

    def __init__(self) -> None:
        self.present = False
        self.fingerprint = ""
        self.claims: dict[str, Any] = {}

    def record(self, header: str | None) -> None:
        if not header or not header.lower().startswith("bearer "):
            self.present = False
            self.fingerprint = ""
            self.claims = {}
            return
        token = header.split(" ", 1)[1].strip()
        self.present = True
        self.fingerprint = hashlib.sha256(token.encode()).hexdigest()[:16]
        self.claims = unverified_claims(token)

    def as_json(self) -> dict[str, Any]:
        audience = self.claims.get("aud")
        return {
            "present": self.present,
            # Distinguishes credentials without revealing them.
            "fingerprint": self.fingerprint,
            "subject": self.claims.get("sub"),
            "audience": audience if isinstance(audience, list) else [audience] if audience else [],
            "authorized_party": self.claims.get("azp"),
            "issuer": self.claims.get("iss"),
            "actor": (self.claims.get("act") or {}).get("sub")
            if isinstance(self.claims.get("act"), dict)
            else None,
        }


def build_mock_app(server_name: str, tools: list[MockTool]) -> Starlette:
    """Build a mock upstream serving ``tools`` on ``/mcp`` (plus ``/debug/credential``).

    An active chaos mode (``acp.mocks.chaos``) overrides normal handling.
    """
    tools_by_name = {t.name: t for t in tools}

    seen = SeenCredential()

    async def handle(request: Request) -> Response:  # noqa: PLR0911
        if request.headers.get("mcp-method") == "tools/call":
            seen.record(request.headers.get("authorization"))
        mode = resolve_mode(request.headers.get(CHAOS_MODE_HEADER))

        if mode is ChaosMode.DISCONNECT:
            return StreamingResponse(_disconnect_stream(), media_type="application/json")

        if mode is ChaosMode.MALFORMED:
            # Deliberately invalid JSON, like a real upstream bug.
            return Response(
                content='{"jsonrpc": "2.0", "id": 1, "result": {truncated',
                media_type="application/json",
                status_code=200,
            )

        try:
            body = await request.json()
        except Exception:  # any parse failure maps to PARSE_ERROR, deliberately broad
            return _json_response(error_response(None, PARSE_ERROR, "invalid JSON body"))

        try:
            rpc_request = JsonRpcRequest.model_validate(body)
        except ValidationError as exc:
            request_id = body.get("id") if isinstance(body, dict) else None
            return _json_response(
                error_response(request_id, INVALID_REQUEST, f"malformed request: {exc}")
            )

        rejection = validate_envelope(rpc_request, request.headers)
        if rejection is not None:
            return _json_response(rejection)

        hang_seconds = resolve_param(
            request.headers.get(CHAOS_PARAM_HEADER), default=DEFAULT_HANG_SECONDS
        )
        async with maybe_hang(mode, hang_seconds):
            pass  # the sleep itself is the point; nothing to do after it

        if mode is ChaosMode.ERROR:
            return _json_response(
                error_response(
                    rpc_request.id,
                    CHAOS_SIMULATED_ERROR,
                    f"chaos: {server_name} is simulating an upstream error",
                )
            )

        result = _dispatch(rpc_request, tools_by_name)

        if mode is ChaosMode.OVERSIZED:
            byte_count = int(
                resolve_param(
                    request.headers.get(CHAOS_PARAM_HEADER), default=DEFAULT_OVERSIZED_BYTES
                )
            )
            if result.result is not None:
                result = JsonRpcResponse(
                    id=result.id, result=_apply_oversized(result.result, byte_count)
                )

        return _json_response(result)

    async def credential(_request: Request) -> Response:
        """What credential the last ``tools/call`` carried.

        The only view of the no-passthrough invariant from outside the gateway process.
        """
        return JSONResponse(seen.as_json())

    return Starlette(
        routes=[
            Route("/mcp", handle, methods=["POST"]),
            Route("/debug/credential", credential, methods=["GET"]),
        ]
    )


def validate_envelope(
    rpc_request: JsonRpcRequest, headers: Mapping[str, str]
) -> JsonRpcResponse | None:
    """Reject what a real 2026-07-28 MCP server would; ``None`` means valid.

    `tests/integration/test_spec_conformance.py` checks these rules against the SDK's own
    validator. Responses stay hand-rolled for chaos (ADR 0004).
    """
    # Fold case ourselves: a plain dict, unlike Starlette's `Headers`, is case-sensitive.
    folded = {name.lower(): value for name, value in headers.items()}
    params = rpc_request.params or {}
    meta = params.get("_meta")

    if not isinstance(meta, dict):
        return error_response(
            rpc_request.id,
            INVALID_PARAMS,
            "params._meta must be an object carrying the required envelope keys: "
            + ", ".join(REQUIRED_META_KEYS),
        )

    if missing := [key for key in REQUIRED_META_KEYS if key not in meta]:
        return error_response(
            rpc_request.id,
            INVALID_PARAMS,
            f"params._meta is missing the required envelope key(s): {', '.join(missing)}",
        )

    # Headers must match the body: proxies authorize on headers.
    if folded.get(MCP_PROTOCOL_VERSION_HEADER.lower()) != meta[REQUIRED_META_KEYS[0]]:
        return error_response(
            rpc_request.id,
            HEADER_MISMATCH,
            f"{MCP_PROTOCOL_VERSION_HEADER} header does not match the envelope's version",
        )

    if folded.get(MCP_METHOD_HEADER.lower()) != rpc_request.method:
        return error_response(
            rpc_request.id,
            HEADER_MISMATCH,
            f"{MCP_METHOD_HEADER} header does not match the request body's method",
        )

    name_key = NAME_BEARING_METHODS.get(rpc_request.method)
    if name_key is not None:
        subject = params.get(name_key)
        if (
            subject is not None
            and decode_header_value(folded.get(MCP_NAME_HEADER.lower())) != subject
        ):
            return error_response(
                rpc_request.id,
                HEADER_MISMATCH,
                f"{MCP_NAME_HEADER} header does not match the request body's {name_key!r} param",
            )

    return None


def _dispatch(rpc_request: JsonRpcRequest, tools_by_name: dict[str, MockTool]) -> JsonRpcResponse:
    """Route a validated request to the right MCP method handler."""
    match rpc_request.method:
        case "tools/list":
            # Per request (no-op unless MOCK_SCHEMA_DRIFT), so drift can start mid-run.
            definitions = apply_drift([t.definition() for t in tools_by_name.values()])
            return JsonRpcResponse(
                id=rpc_request.id,
                result=tool_definitions_result(definitions, ttl_ms=CATALOGUE_TTL_MS),
            )
        case "tools/call":
            return _dispatch_tools_call(rpc_request, tools_by_name)
        case _:
            return error_response(
                rpc_request.id, METHOD_NOT_FOUND, f"unknown method: {rpc_request.method}"
            )


def _dispatch_tools_call(
    rpc_request: JsonRpcRequest, tools_by_name: dict[str, MockTool]
) -> JsonRpcResponse:
    params = rpc_request.params or {}
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not isinstance(name, str):
        return error_response(rpc_request.id, INVALID_PARAMS, "params.name must be a string")

    tool = tools_by_name.get(name)
    if tool is None:
        return error_response(rpc_request.id, INVALID_PARAMS, f"unknown tool: {name}")

    result = _run_tool(tool, arguments)
    return JsonRpcResponse(id=rpc_request.id, result=call_tool_result(result))


def _run_tool(tool: MockTool, arguments: dict[str, Any]) -> CallToolResult:
    """Run a handler; a raised exception becomes an ``isError`` result, per MCP convention."""
    try:
        return tool.handler(arguments)
    except Exception as exc:  # deliberately broad: any handler failure becomes isError
        return CallToolResult(
            content=[TextContent(text=f"{tool.name} failed: {exc}")], is_error=True
        )


__all__ = ["MockTool", "ToolHandler", "build_mock_app"]
