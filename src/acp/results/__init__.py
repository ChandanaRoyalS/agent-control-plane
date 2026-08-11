"""Result caching: repeat an answer to the person who asked for it, and nobody else.

Phase 4's last control. Rate limits, costs and quotas bound how much an agent
may spend; this bounds how often the estate is asked the same question. A read
the same caller makes twice within a few seconds should not cost two upstream
round trips, two credential exchanges and two budget draws.

The whole risk is in one function — `cache.key_for`. See ADR 0035.
"""

from acp.results.cache import KEY_VERSION, ResultCache, ResultKey, key_for
from acp.results.loader import load_cacheable
from acp.results.table import MAX_TTL_SECONDS, CacheableTools

__all__ = [
    "KEY_VERSION",
    "MAX_TTL_SECONDS",
    "CacheableTools",
    "ResultCache",
    "ResultKey",
    "key_for",
    "load_cacheable",
]
