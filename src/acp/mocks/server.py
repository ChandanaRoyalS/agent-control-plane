"""A generic factory for building a mock MCP upstream as a Starlette ASGI app.

Each mock server is just a name plus a list of ``MockTool`` definitions — see
``mock_a.py`` and ``mock_b.py`` for the two concrete servers. All the protocol
and chaos handling lives here, once, so the two servers stay a declarative list
of tools and nothing else.
"""

from __future__ import annotations

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
"""What these mocks advertise on `tools/list`, so caching is observable.

A real upstream picks this from how often its catalogue actually changes. Sixty
seconds is short enough that a demo does not have to wait around and long enough
that the second request in a burst is obviously a cache hit.
"""

ToolHandler = Callable[[dict[str, Any]], CallToolResult]
"""A deterministic function from tool arguments to a result.

Deliberately synchronous: mock tool logic has no I/O, and keeping handlers sync
means every test can assert on output without an event loop of its own beyond
the one already driving the request.
"""


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
    """Yield one partial chunk, then blow up.

    Starlette's ``StreamingResponse`` has already sent HTTP headers by the time
    the second ``yield`` is reached, so raising here reproduces a connection
    that dies mid-body rather than one that never starts.
    """
    yield b'{"jsonrpc": "2.0", "id": 1, "result": {"chaos": "disconnect'
    raise Disconnected


def _apply_oversized(result: dict[str, Any], byte_count: int) -> dict[str, Any]:
    """Inflate a result payload past any reasonable size limit.

    Appended as an extra key rather than mutating existing fields, so this
    works identically for a ``tools/list`` result and a ``tools/call`` result
    without either method needing chaos-specific logic.
    """
    return {**result, "_chaos_filler": oversized_text(byte_count)}


def build_mock_app(server_name: str, tools: list[MockTool]) -> Starlette:
    """Build a mock MCP upstream exposing ``tools`` over a single ``/mcp`` route.

    Speaks JSON-RPC 2.0 with the MCP tool primitives (``tools/list``,
    ``tools/call``). Every request is first checked for a chaos override —
    see ``acp.mocks.chaos`` — which, when active, short-circuits normal
    handling entirely.
    """
    tools_by_name = {t.name: t for t in tools}

    async def handle(request: Request) -> Response:  # noqa: PLR0911
        mode = resolve_mode(request.headers.get(CHAOS_MODE_HEADER))

        if mode is ChaosMode.DISCONNECT:
            return StreamingResponse(_disconnect_stream(), media_type="application/json")

        if mode is ChaosMode.MALFORMED:
            # Deliberately not valid JSON: a real upstream bug looks like this,
            # not like a well-formed error the client can parse cleanly.
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

    return Starlette(routes=[Route("/mcp", handle, methods=["POST"])])


def validate_envelope(
    rpc_request: JsonRpcRequest, headers: Mapping[str, str]
) -> JsonRpcResponse | None:
    """Reject anything a real MCP server would reject. ``None`` means valid.

    This exists because of a bug the whole test suite missed. The gateway sent
    a `_meta` envelope of its own invention, these mocks accepted it, and 297
    passing tests said nothing — a mock that agrees with your client proves only
    that you wrote both. So the mocks now enforce the 2026-07-28 rules, and
    `tests/integration/test_spec_conformance.py` checks these rules against the
    SDK's own validator so this implementation cannot drift either.

    ADR 0004 still holds: *responses* stay hand-rolled, because chaos modes have
    to emit genuinely malformed output that a real server would never produce.
    Validating *requests* strictly is the opposite concern and pulls the other
    way.
    """
    # Folded to lowercase rather than trusting the caller's mapping to be
    # case-insensitive. Starlette's `Headers` is; a plain dict is not, and a
    # validator that quietly passes or fails depending on which one it was
    # handed is a trap for whoever calls it next. HTTP field names are
    # case-insensitive by definition, so this is the correct reading anyway.
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

    # The headers are checked against the body, not merely for presence. That
    # is the point of them: a proxy authorizes on the cheap header, so a server
    # that let the body say something else would be authorizing one method and
    # executing another.
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
            # `apply_drift` is a no-op unless MOCK_SCHEMA_DRIFT is set, and is
            # applied here rather than at startup so the catalogue can be
            # changed under a running gateway — which is the situation task 20
            # exists for and the only honest way to demonstrate it.
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
    """Execute a tool handler, converting a raised exception into isError.

    Mirrors the real MCP convention (see ``jsonrpc.py`` docstring): execution
    failures are reported *inside* a successful JSON-RPC result, not as a
    JSON-RPC error, because the request itself was well-formed.
    """
    try:
        return tool.handler(arguments)
    except Exception as exc:  # deliberately broad: any handler failure becomes isError
        return CallToolResult(
            content=[TextContent(text=f"{tool.name} failed: {exc}")], is_error=True
        )


__all__ = ["MockTool", "ToolHandler", "build_mock_app"]
