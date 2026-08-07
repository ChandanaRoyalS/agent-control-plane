"""An async JSON-RPC client for one upstream MCP server.

Scope note: this deliberately contains no retries, no circuit breaker and no
health checking. Those are tasks 13, 14 and 18, and they wrap this rather than
living inside it — a client that silently retries is a client you cannot build a
correct circuit breaker on top of, because the breaker can no longer see how
many attempts actually failed.

What it does own: connection pooling, layered timeouts, and turning every
possible failure into a member of the exception taxonomy.
"""

from __future__ import annotations

import itertools
import logging
import time
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Self

import httpx

from acp import __version__
from acp.exceptions import (
    ACPError,
    UpstreamProtocolError,
    UpstreamRejectedError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from acp.observability import metrics, semconv, tracing
from acp.upstream.config import UpstreamConfig
from acp.upstream.envelope import routing_headers, with_envelope
from acp.upstream.models import PROTOCOL_VERSION, CallToolResult, ListToolsResult

logger = logging.getLogger(__name__)

CLIENT_NAME = "agent-control-plane"
"""Identity sent in every request's envelope, since there is no handshake to
introduce ourselves in."""


class UpstreamClient:
    """Talks JSON-RPC to a single upstream MCP server.

    Construct with an injected ``httpx.AsyncClient`` — or use :meth:`connect`,
    which builds a correctly configured one and closes it on exit. Injection is
    what lets tests drive a mock upstream in-process through ``ASGITransport``
    with no sockets, without this class needing any test-only branches.
    """

    def __init__(self, config: UpstreamConfig, http: httpx.AsyncClient) -> None:
        self.config = config
        self._http = http
        # Monotonic per-client request IDs. JSON-RPC only requires that an id be
        # unique among in-flight requests on a connection, so a simple counter
        # is sufficient and makes correlating a response to a request trivial
        # when reading a packet capture or a log.
        self._ids = itertools.count(1)

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    async def connect(cls, config: UpstreamConfig) -> Self:
        """Build a client with a pool and timeouts derived from ``config``."""
        return cls(config, httpx.AsyncClient(timeout=_timeout(config), limits=_limits(config)))

    async def aclose(self) -> None:
        """Close the connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- MCP methods -------------------------------------------------------

    async def list_tools(self) -> ListToolsResult:
        """Fetch the upstream's tool catalogue, with its freshness hints."""
        result = await self._request("tools/list")
        raw_tools = result.get("tools")
        if not isinstance(raw_tools, list):
            raise UpstreamProtocolError(
                "tools/list result has no `tools` array",
                upstream=self.config.name,
                details={"received_keys": sorted(result)},
            )
        try:
            return ListToolsResult.model_validate(result)
        except Exception as exc:
            raise UpstreamProtocolError(
                f"tools/list returned a malformed tool definition: {exc}",
                upstream=self.config.name,
            ) from exc

    async def invalidate(self) -> None:
        """Nothing to forget. This layer holds no cache."""
        return

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Invoke one tool.

        A tool that runs and fails returns normally with ``is_error`` set — that
        is a result, not an exception. Only transport and protocol failures
        raise.
        """
        result = await self._request(
            "tools/call",
            {"name": name, "arguments": dict(arguments or {})},
            tool_name=name,
        )
        try:
            return CallToolResult.model_validate(result)
        except Exception as exc:
            raise UpstreamProtocolError(
                f"tools/call returned a malformed result: {exc}",
                upstream=self.config.name,
                details={"tool": name},
            ) from exc

    # -- transport ---------------------------------------------------------

    async def _request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        tool_name: str | None = None,
    ) -> dict[str, Any]:
        """Send one JSON-RPC request and return its ``result`` object.

        Every failure path out of this method raises a member of the exception
        taxonomy. Nothing else escapes.
        """
        request_id = next(self._ids)
        attributes = semconv.client_attributes(
            method=method,
            upstream=self.config.name,
            url=self.config.url,
            tool=tool_name,
            request_id=request_id,
            protocol_version=PROTOCOL_VERSION,
        )
        # The span is opened *before* the body is built, and that ordering is
        # the point: the trace context injected below is this span's, so the
        # upstream's own server span nests underneath this client span rather
        # than beside it. Open it afterwards and the trace loses its shape.
        span_name = semconv.span_name(method, semconv.client_target(self.config.name, tool_name))
        with tracing.client_span(span_name, attributes) as span:
            return await self._send(method, params, tool_name, request_id, span)

    async def _send(
        self,
        method: str,
        params: Mapping[str, Any] | None,
        tool_name: str | None,
        request_id: int,
        span: Any,
    ) -> dict[str, Any]:
        # The envelope lives in `params._meta`, so `params` is always present
        # — even for a method that takes no arguments. A `tools/list` with no
        # params is not a valid 2026-07-28 request, and a real server rejects
        # it with -32602 before the method is ever dispatched.
        #
        # The W3C trace context rides in the same `_meta`, unprefixed, per
        # SEP-414. Empty when nothing is being traced, in which case the request
        # is byte-for-byte what it was before tracing existed.
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": with_envelope(
                params, CLIENT_NAME, __version__, tracing.current_trace_context()
            ),
        }
        # Derived from the body rather than assembled alongside it, so the
        # headers cannot drift from what they are asserting about. A server
        # rejects a request whose header and body disagree.
        headers = routing_headers(method, body["params"])

        started = time.perf_counter()
        try:
            response = await self._http.post(self.config.url, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            self._observe(method, tool_name, started, "timeout")
            tracing.mark_failed(span, semconv.error_attributes(exc), "timeout")
            raise UpstreamTimeoutError(
                f"{self.config.name} did not respond within its timeout budget",
                upstream=self.config.name,
                details={"method": method},
            ) from exc
        except httpx.HTTPError as exc:
            # Covers connection refused, DNS failure, TLS errors, and a
            # connection dropped mid-response. All mean "could not complete the
            # exchange", which is a different thing from "answered badly".
            self._observe(method, tool_name, started, "unavailable")
            tracing.mark_failed(span, semconv.error_attributes(exc), "unavailable")
            raise UpstreamUnavailableError(
                f"{self.config.name} is unreachable: {exc}",
                upstream=self.config.name,
                details={"method": method},
            ) from exc

        try:
            result = self._parse(response, method)
        except ACPError as exc:
            self._observe(method, tool_name, started, "rejected", error=type(exc).__name__)
            tracing.mark_failed(
                span,
                semconv.error_attributes(exc, status_code=getattr(exc, "upstream_code", None)),
                "rejected",
            )
            raise

        self._observe(method, tool_name, started, "ok", status=response.status_code)
        return result

    def _observe(
        self,
        method: str,
        tool_name: str | None,
        started: float,
        outcome: str,
        **fields: object,
    ) -> None:
        """One event per upstream call, whatever happened.

        This is the layer that actually touches the network, so it is the only
        place that can time it honestly — a wrapper further out would be timing
        its own retries and backoff as well. It is also why `httpx` itself is
        turned down to WARNING: an INFO line per request from the library would
        say the same thing with less context.
        """
        elapsed = time.perf_counter() - started
        logger.info(
            "upstream.call",
            extra={
                "upstream": self.config.name,
                "operation": method,
                "tool": tool_name,
                "outcome": outcome,
                # Milliseconds in the log because a human reads it; seconds in
                # the histogram because Prometheus convention is base units.
                "duration_ms": round(elapsed * 1000, 2),
                **fields,
            },
        )
        metrics.record_upstream_call(
            upstream=self.config.name,
            method=method,
            # Already resolved against this upstream's catalogue by the registry
            # before it reached here, so it is a bounded value rather than
            # whatever the agent typed.
            tool=metrics.tool_label(tool_name),
            outcome=outcome,
            duration_seconds=elapsed,
        )

    def _parse(self, response: httpx.Response, method: str) -> dict[str, Any]:
        """Turn an HTTP response into a JSON-RPC result, or raise."""
        if response.is_error:  # httpx: any 4xx or 5xx
            raise UpstreamUnavailableError(
                f"{self.config.name} returned HTTP {response.status_code}",
                upstream=self.config.name,
                details={"method": method, "status": response.status_code},
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise UpstreamProtocolError(
                f"{self.config.name} returned a body that is not JSON",
                upstream=self.config.name,
                details={"method": method},
            ) from exc

        if not isinstance(payload, dict):
            raise UpstreamProtocolError(
                f"{self.config.name} returned JSON that is not an object",
                upstream=self.config.name,
                details={"method": method},
            )

        if "error" in payload:
            error = payload["error"]
            if not isinstance(error, dict) or "code" not in error:
                raise UpstreamProtocolError(
                    f"{self.config.name} returned a malformed JSON-RPC error object",
                    upstream=self.config.name,
                    details={"method": method},
                )
            raise UpstreamRejectedError(
                str(error.get("message", "upstream rejected the request")),
                upstream=self.config.name,
                upstream_code=int(error["code"]),
                details={"method": method},
            )

        result = payload.get("result")
        if not isinstance(result, dict):
            raise UpstreamProtocolError(
                f"{self.config.name} returned neither a `result` object nor an `error`",
                upstream=self.config.name,
                details={"method": method},
            )
        return result


def _timeout(config: UpstreamConfig) -> httpx.Timeout:
    return httpx.Timeout(
        connect=config.connect_timeout,
        read=config.read_timeout,
        write=config.write_timeout,
        pool=config.pool_timeout,
    )


def _limits(config: UpstreamConfig) -> httpx.Limits:
    return httpx.Limits(
        max_connections=config.max_connections,
        max_keepalive_connections=config.max_keepalive_connections,
    )
