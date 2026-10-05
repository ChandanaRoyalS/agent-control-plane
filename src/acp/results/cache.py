"""A bounded tool-result cache, and `key_for`, which decides whose result it is.

A key on tool and arguments alone would serve alice's records to bob, unseen by any
log (ADR 0022's lesson, one layer up). So the key covers tenant, subject, actor
(upstreams may scope by agent), upstream, tool and canonical arguments under a
version tag; when in doubt, prefer a miss to a disclosure. Keys are SHA-256 digests,
so logs never carry identities or arguments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from acp.upstream.models import CallToolResult

logger = logging.getLogger(__name__)

KEY_VERSION: Final = "acp-result-v2"
"""Stamped into every key; bump it whenever key material changes (v2 added the tenant).

Old entries then miss instead of being reinterpreted under the new scheme.
"""

DEFAULT_MAX_ENTRIES: Final = 512
"""Ceiling on held results, since callers choose the keys; below the credential cache's
1024 because each entry is a whole tool response."""


@dataclass(frozen=True, slots=True)
class ResultKey:
    """A cache key: one digest field, so no lookup can match on a subset of the parts."""

    digest: str

    @property
    def short(self) -> str:
        """The first twelve hex characters, for logs."""
        return self.digest[:12]


def key_for(
    *,
    tenant: str | None,
    subject: str,
    actor: str | None,
    upstream: str,
    tool: str,
    arguments: Mapping[str, Any],
) -> ResultKey | None:
    """Return the key for this call, or ``None`` if the arguments are not JSON-encodable.

    No fallback encoding (`repr`, `str`), as it could collide two callers' keys.
    Arguments are canonicalised (sorted keys, compact) for hit rate only.
    """
    try:
        encoded_arguments = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        logger.debug("results.unkeyable", extra={"tool": tool})
        return None

    # A JSON list, not a joined string, so no field can forge a boundary.
    material = json.dumps(
        [KEY_VERSION, tenant, subject, actor, upstream, tool, encoded_arguments],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return ResultKey(digest=hashlib.sha256(material.encode("utf-8")).hexdigest())


@dataclass
class _Entry:
    result: CallToolResult
    expires_at: float


class ResultCache:
    """Tool results held per principal for their table ttl; bounded LRU.

    Not single-flight: concurrent identical calls both reach the upstream, so a tool
    wrongly marked cacheable never has a side effect silently skipped.
    """

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._entries: OrderedDict[ResultKey, _Entry] = OrderedDict()
        self._max_entries = max_entries
        # Monotonic, so a wall-clock jump cannot extend an entry's life.
        self._clock = clock or time.monotonic
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: ResultKey) -> CallToolResult | None:
        """Return a deep copy of the live result, or ``None``; copies stop callers mutating it."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() >= entry.expires_at:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry.result.model_copy(deep=True)

    def put(self, key: ResultKey, result: CallToolResult, *, ttl: float) -> None:
        """Store a copy of ``result`` for ``ttl`` seconds.

        Error results are never cached (checked here so no caller can forget), and a
        non-positive ttl stores nothing.
        """
        if result.is_error:
            return
        if ttl <= 0:
            return

        self._entries[key] = _Entry(result.model_copy(deep=True), self._clock() + ttl)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            evicted, _ = self._entries.popitem(last=False)
            logger.debug("results.evicted", extra={"key": evicted.short})

    def record(self, *, hit: bool) -> None:
        if hit:
            self.hits += 1
        else:
            self.misses += 1

    def clear(self) -> None:
        self._entries.clear()
