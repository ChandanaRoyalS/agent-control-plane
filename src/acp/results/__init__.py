"""Result caching: repeat an answer only to the caller who asked for it.

Saves upstream round trips for repeated reads. The whole risk is in `cache.key_for`
(ADR 0035).
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
