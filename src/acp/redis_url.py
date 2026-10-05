"""The one check every setting that names a Redis makes.

Two settings point at a Redis — the approval store (ADR 0066) and the budget
store (ADR 0067) — and both must refuse a URL that is not one at load, where
the message can name the setting, rather than at the first connection, where
the failure would be a gateway holding calls in nothing. The check is the same
and lives once.
"""

from __future__ import annotations

from typing import Final

REDIS_SCHEMES: Final = ("redis://", "rediss://", "unix://")


def check_redis_url(setting: str, value: str) -> str:
    """``value`` unchanged if it is empty or a Redis URL; ``ValueError`` otherwise."""
    if value and not value.startswith(REDIS_SCHEMES):
        schemes = ", ".join(REDIS_SCHEMES)
        msg = f"{setting} must start with one of {schemes}"
        raise ValueError(msg)
    return value
