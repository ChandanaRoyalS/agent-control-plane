"""Load the cacheable-tools table from a YAML document, or refuse to start.

The same shape as ``acp.budget.loader``: a mapping under a single key, errors
that name the file and the offending entry, and an empty file treated as a
question rather than an answer. A deployment that cannot say what it meant
should be told so at boot, by a message a human can act on, rather than
discovering it on the first request.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from acp.exceptions import ConfigurationError
from acp.results.table import MAX_TTL_SECONDS, CacheableTools


def _validate_ttl(name: str, value: object, path: Path) -> float:
    # `bool` first, because it is a subclass of `int` and `ttl: true` would
    # otherwise silently mean one second.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"cache file {str(path)!r}: ttl for {name!r} must be a number, got {value!r}"
        raise ConfigurationError(msg)

    ttl = float(value)
    if ttl < 0:
        msg = f"cache file {str(path)!r}: ttl for {name!r} must not be negative"
        raise ConfigurationError(msg)
    if ttl > MAX_TTL_SECONDS:
        # Refused rather than clamped. Clamping would let a file ask for an hour
        # and get five minutes with nobody told, so the deployment's stated
        # intent and its actual behaviour would differ permanently and silently.
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

    # No `default` key, unlike the cost table, and the asymmetry is the point.
    # A default cost of 1.0 applied to an unlisted tool is a sensible guess about
    # money. A default *ttl* applied to an unlisted tool would make every tool in
    # the estate cacheable the moment somebody creates this file — including the
    # writes. Caching is opt-in per tool, with no way to opt in wholesale.
    ttls = {name: _validate_ttl(name, value, path) for name, value in raw_tools.items()}
    return CacheableTools(ttls=ttls)
