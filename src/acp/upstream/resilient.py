"""An upstream client that retries, wrapped around one that does not.

A separate layer so the breaker beneath it counts each attempt, and
``UpstreamClient`` stays one call in, one request out (ADR 0006).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Self

from acp.observability import metrics
from acp.upstream.config import UpstreamConfig
from acp.upstream.models import CallToolResult, ListToolsResult
from acp.upstream.protocol import Upstream
from acp.upstream.retry import RetryPolicy, with_retry

logger = logging.getLogger(__name__)


def policy_for(config: UpstreamConfig) -> RetryPolicy:
    """Derive the retry policy from an upstream's configuration."""
    return RetryPolicy(
        max_attempts=config.max_attempts,
        initial_backoff=config.initial_backoff,
        max_backoff=config.max_backoff,
    )


class RetryingUpstreamClient:
    """Wraps any ``Upstream``, retrying only what is safe to retry.

    Layer order is set in ``acp.upstream.factory``.
    """

    def __init__(self, inner: Upstream, policy: RetryPolicy | None = None) -> None:
        self._inner = inner
        self._policy = policy or policy_for(inner.config)

    @property
    def config(self) -> UpstreamConfig:
        return self._inner.config

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def invalidate(self) -> None:
        await self._inner.invalidate()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- operations --------------------------------------------------------

    async def list_tools(self) -> ListToolsResult:
        """Always retryable: listing tools is a read with no side effects."""
        return await with_retry(
            self._inner.list_tools,
            self._policy,
            on_retry=self._log_retry("tools/list"),
        )

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> CallToolResult:
        """Retried only if this upstream declares the tool idempotent.

        A timeout does not mean the tool did not run, so retrying others could
        perform the action twice.
        """
        if name not in self.config.idempotent_tools:
            return await self._inner.call_tool(name, arguments)

        async def operation() -> CallToolResult:
            return await self._inner.call_tool(name, arguments)

        return await with_retry(
            operation, self._policy, on_retry=self._log_retry("tools/call", tool=name)
        )

    def _log_retry(self, operation: str, tool: str | None = None) -> Any:
        """Build a callback that records each retry as a metric and an ``upstream.retry`` event."""

        def observe(attempt: int, delay: float, exc: BaseException) -> None:
            metrics.record_retry(upstream=self.config.name, method=operation)
            logger.warning(
                "upstream.retry",
                extra={
                    "upstream": self.config.name,
                    "operation": operation,
                    "tool": tool,
                    "attempt": attempt,
                    "max_attempts": self._policy.max_attempts,
                    "delay_ms": round(delay * 1000, 2),
                    "error": type(exc).__name__,
                },
            )

        return observe
