"""An async JSON-RPC client for one upstream MCP server.

Owns pooling, layered timeouts and mapping every failure into the exception
taxonomy. Retries, breaker and health checks are wrapping layers (ADR 0006).
"""

from __future__ import annotations

import itertools
import logging
import time
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Final, Self

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
from acp.upstream.protocol import Credentials

logger = logging.getLogger(__name__)

_TRANSIENT_STATUSES: Final = frozenset({408, 429})
"""4xx codes describing the upstream's state, not the request: timeout, rate limit."""

_SERVER_ERROR_FLOOR: Final = 500

CLIENT_NAME = "agent-control-plane"
"""Identity sent in every request's envelope."""


class UpstreamClient:
    """Talks JSON-RPC to a single upstream MCP server.

    Takes an injected ``httpx.AsyncClient`` (tests use ``ASGITransport``), or use
    :meth:`connect` to build a configured one.
    """

    def __init__(
        self,
        config: UpstreamConfig,
        http: httpx.AsyncClient,
        credentials: Credentials | None = None,
        secret: str | None = None,
    ) -> None:
        self.config = config
        self._http = http
        # Resolved at startup, so a missing secret fails there, not per request.
        self._secret = secret
        # `None` when no token exchange is configured.
        self._credentials = credentials
        # JSON-RPC ids need only be unique among in-flight requests.
        self._ids = itertools.count(1)

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    async def connect(
        cls,
        config: UpstreamConfig,
        credentials: Credentials | None = None,
        secret: str | None = None,
    ) -> Self:
        """Build a client with a pool and timeouts derived from ``config``."""
        return cls(
            config,
            httpx.AsyncClient(timeout=_timeout(config), limits=_limits(config)),
            credentials,
            secret,
        )

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

    async def _credential(self) -> tuple[str, str] | None:
        """The header and value this call carries, if any.

        A static secret goes in the configured header; an exchanged credential is
        minted per call and always sent in `Authorization` (RFC 6750). The two are
        mutually exclusive in config.
        """
        if self._secret is not None:
            scheme = self.config.credential_scheme
            value = f"{scheme} {self._secret}" if scheme else self._secret
            return self.config.credential_header, value

        if self._credentials is None or not self.config.audience:
            return None
        authorization = await self._credentials.authorization_for(
            self.config.name, self.config.audience, self.config.resource
        )
        return ("Authorization", authorization) if authorization is not None else None

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
        """Invoke one tool; a tool failure returns ``is_error``, transport errors raise."""
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
        """Send one JSON-RPC request and return its ``result``; failures raise ``ACPError``s."""
        request_id = next(self._ids)
        attributes = semconv.client_attributes(
            method=method,
            upstream=self.config.name,
            url=self.config.url,
            tool=tool_name,
            request_id=request_id,
            protocol_version=PROTOCOL_VERSION,
        )
        # Span opened before the body is built, so the injected trace context is
        # this span's and the upstream's span nests under it.
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
        # `params` is always present (it holds the envelope); without it a real
        # server rejects with -32602. Trace context rides in `_meta` (SEP-414).
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": with_envelope(
                params, CLIENT_NAME, __version__, tracing.current_trace_context()
            ),
        }
        # Derived from the body so headers cannot disagree with it.
        headers = routing_headers(method, body["params"])

        # Minted before the timer starts, so identity latency is not upstream
        # latency. `CredentialExchangeError` propagates; the breaker ignores it.
        credential = await self._credential()
        if credential is not None:
            headers[credential[0]] = credential[1]

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
            # Refused, DNS, TLS, or dropped mid-response: no exchange completed.
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
        """Log and record one event per upstream call; only this layer times the network alone."""
        elapsed = time.perf_counter() - started
        logger.info(
            "upstream.call",
            extra={
                "upstream": self.config.name,
                "operation": method,
                "tool": tool_name,
                "outcome": outcome,
                # ms for humans here; the histogram uses seconds.
                "duration_ms": round(elapsed * 1000, 2),
                **fields,
            },
        )
        metrics.record_upstream_call(
            upstream=self.config.name,
            method=method,
            # Bounded: the registry resolved it against the catalogue.
            tool=metrics.tool_label(tool_name),
            outcome=outcome,
            duration_seconds=elapsed,
        )

    def _parse(self, response: httpx.Response, method: str) -> dict[str, Any]:
        """Turn an HTTP response into a JSON-RPC result, or raise."""
        if response.is_error:  # httpx: any 4xx or 5xx
            status = response.status_code
            if status in _TRANSIENT_STATUSES or status >= _SERVER_ERROR_FLOOR:
                # Upstream struggling: recoverable, retried, counted by the breaker.
                raise UpstreamUnavailableError(
                    f"{self.config.name} returned HTTP {status}",
                    upstream=self.config.name,
                    details={"method": method, "status": status},
                )
            # Other 4xx: this request is wrong. Not retried or counted by the
            # breaker, so one bad API key cannot withdraw a healthy upstream.
            raise UpstreamProtocolError(
                f"{self.config.name} returned HTTP {status}",
                upstream=self.config.name,
                details={"method": method, "status": status},
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
            # A non-integer code is a malformed error object; checked rather
            # than cast so nothing escapes the taxonomy.
            if (
                not isinstance(error, dict)
                or not isinstance(error.get("code"), int)
                or isinstance(error.get("code"), bool)
            ):
                raise UpstreamProtocolError(
                    f"{self.config.name} returned a malformed JSON-RPC error object",
                    upstream=self.config.name,
                    details={"method": method},
                )
            raise UpstreamRejectedError(
                str(error.get("message", "upstream rejected the request")),
                upstream=self.config.name,
                upstream_code=error["code"],
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
