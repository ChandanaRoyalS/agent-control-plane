"""An upstream client that retries, wrapped around one that does not.

Deliberately a wrapper rather than logic inside ``UpstreamClient``. A client
that silently retries is a client you cannot build a correct circuit breaker on
top of (task 14), because the breaker can no longer see how many attempts
actually failed — three retries of one call would look like one failure, and the
breaker would take three times too long to open. Keeping the retrying separate
means each layer sees the truth.

It also keeps ``UpstreamClient`` honest: one call in, one request out, which is
what makes its own tests meaningful.
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

    Typed against the protocol rather than the concrete client so it can sit on
    top of the guard layer as well as directly on a client. It satisfies the
    same protocol itself, which is what makes the layers stack in the first
    place — see ``acp.upstream.factory`` for the order they are built in and
    why that order is load-bearing.
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

        The unsafe case is worth stating plainly: a timeout means the gateway
        got no answer, *not* that nothing happened. The upstream may have run
        the tool and failed to reply. Retrying then performs the action twice,
        and neither the gateway nor the agent can tell.
        """
        if name not in self.config.idempotent_tools:
            return await self._inner.call_tool(name, arguments)

        async def operation() -> CallToolResult:
            return await self._inner.call_tool(name, arguments)

        return await with_retry(
            operation, self._policy, on_retry=self._log_retry("tools/call", tool=name)
        )

    def _log_retry(self, operation: str, tool: str | None = None) -> Any:
        """A retry nobody can see turns a degraded upstream into mystery latency.

        An event with fields rather than a sentence: `upstream.retry` can be
        counted per upstream and per error type without anyone writing a regular
        expression against a message that will eventually be reworded. Task 17
        turns exactly these fields into a metric.
        """

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
