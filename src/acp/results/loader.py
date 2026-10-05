"""Load the cacheable-tools table from a YAML document, or refuse to start.

Like ``acp.budget.loader``: errors name the file and entry, and an empty file is
refused at boot rather than guessed at.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from acp.exceptions import ConfigurationError
from acp.results.table import MAX_TTL_SECONDS, CacheableTools


def _validate_ttl(name: str, value: object, path: Path) -> float:
    # `bool` first: it subclasses `int`, so `ttl: true` would mean one second.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"cache file {str(path)!r}: ttl for {name!r} must be a number, got {value!r}"
        raise ConfigurationError(msg)

    ttl = float(value)
    if ttl < 0:
        msg = f"cache file {str(path)!r}: ttl for {name!r} must not be negative"
        raise ConfigurationError(msg)
    if ttl > MAX_TTL_SECONDS:
        # Refused, not clamped, so stated intent and behaviour never silently differ.
        msg = (
            f"cache file {str(path)!r}: ttl for {name!r} is {ttl}s, over the "
            f"{MAX_TTL_SECONDS}s ceiling. A cached result outlives an upstream "
            f"entitlement change by up to its ttl, so the ceiling is deliberate."
        )
        raise ConfigurationError(msg)
    return ttl


def load_cacheable(path: Path) -> CacheableTools:
    """Read and validate the cache document, or raise ``ConfigurationError``."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read cache file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"cache file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc

    if document is None:
        msg = (
            f"cache file {str(path)!r} is empty. Write `tools: {{}}` to mean "
            f"'cache nothing', or list the tools whose results may be cached."
        )
        raise ConfigurationError(msg)

    if not isinstance(document, dict):
        msg = f"cache file {str(path)!r} must be a mapping with a `tools` key"
        raise ConfigurationError(msg)

    raw_tools = document.get("tools", {})
    if not isinstance(raw_tools, dict):
        msg = f"cache file {str(path)!r}: `tools` must be a mapping of tool to ttl"
        raise ConfigurationError(msg)

    # No `default` key, unlike costs: a default ttl would make every tool cacheable,
    # writes included. Caching is opt-in per tool only.
    ttls = {name: _validate_ttl(name, value, path) for name, value in raw_tools.items()}
    return CacheableTools(ttls=ttls)
