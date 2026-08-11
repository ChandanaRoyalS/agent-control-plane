"""Holding a tool result, and the one line that decides whose result it is.

**The key is the whole task.** Everything else here is a dictionary with a size
limit and a clock. Get the key wrong and this is a data breach whose only
artefact is its absence:

Key on the tool and the arguments — the obvious thing, and what every
general-purpose cache decorator does — and alice searches, bob makes the
identical search a second later, and bob reads alice's records. Every functional
test passes, because every functional test asks whether a search returns search
results, and it does. The upstream's audit log shows one read, by alice, which
is true. Bob's read appears nowhere at all: not upstream, because the upstream
was never called, and not in the gateway's log, because a cache hit is the
system working.

This is ADR 0022 one layer up and worse. Task 30's bad key would have served
alice's *credential* to bob — serious, but a credential can be rotated, an
exchange can be counted, an `aud` claim can be checked. A bad result key serves
the data itself, with no credential involved.

**So the key names everything that could change the answer.** The subject, the
actor, the upstream, the tool, and the arguments — canonically encoded, under a
version tag. Over-specificity costs a cache miss. Under-specificity costs a
disclosure. Where the two trade off, the answer is always the one that costs a
miss; that is the rule task 30 settled on, and the only one that stays right
when somebody adds a claim next year that nobody here has thought about.

**Why the actor is in there.** Two agents acting for alice do not share an
entry. That is deliberate over-specificity: this gateway's entire model is that
a call is made by an agent *acting for* a human, and an upstream may
legitimately scope by which agent — a support bot that sees redacted fields, a
research agent restricted to public records. Leaving the actor out would collapse
two different answers into one.

**A digest, never the parts.** The key prints as hex, so an entry that reaches a
log line, a traceback or a debugger carries no subject, no arguments and no
query text. Arguments in particular are the caller's data, and a cache key is
exactly the sort of thing that ends up in a debug log.
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

KEY_VERSION: Final = "acp-result-v1"
"""Stamped into every key.

So the encoding below can change — a new field, a different canonical form —
without any chance of an entry written under the old scheme being read under the
new one. Without it, a change to what goes into the key silently reinterprets
every entry already in memory, which is the one failure mode a cache must never
have.
"""

DEFAULT_MAX_ENTRIES: Final = 512
"""Ceiling on held results, and a security limit before a memory one.

An authenticated caller chooses the keys: vary one argument in a loop and every
distinct call is retained until it expires. A bound turns that into eviction of
somebody else's entry, which costs an upstream call rather than the process.

Lower than the credential cache's 1024, because a result is a whole tool
response rather than a token — bounded by count, but each entry is far larger.
"""


@dataclass(frozen=True, slots=True)
class ResultKey:
    """What makes two calls the same call, from the same person, for caching.

    One field, because everything that matters is inside the digest and nothing
    outside it should be comparable. A dataclass with `subject` and `tool` as
    separate fields would invite somebody to write a lookup that matches on a
    subset — which is precisely the bug.
    """

    digest: str

    @property
    def short(self) -> str:
        """Twelve characters, for logs. Enough to tell two entries apart in a
        trace and useless for anything else."""
        return self.digest[:12]


def key_for(
    *,
    subject: str,
    actor: str | None,
    upstream: str,
    tool: str,
    arguments: Mapping[str, Any],
) -> ResultKey | None:
    """The key for this call, or ``None`` when it cannot be keyed safely.

    ``None`` when the arguments will not encode — a value carrying something
    JSON cannot represent. **Refusing to cache is the only correct answer
    there.** The alternative is a fallback encoding, `repr()` or `str()`, and
    both can map two different argument sets onto one string. A cache miss costs
    a round trip; a key collision between two callers costs the thing this whole
    module exists to prevent.

    Arguments are canonicalised — keys sorted, no insignificant whitespace — so
    that `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` are one entry rather than two.
    That is a hit-rate concern, not a safety one: two spellings of the same call
    hashing differently is a miss, never a leak.
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

    # A list rather than a concatenation, encoded as JSON, so no field can be
    # made to look like the start of the next one. Joining with a separator
    # invites a subject containing that separator to forge a different key —
    # the classic canonicalisation bug, and free to avoid here.
    material = json.dumps(
        [KEY_VERSION, subject, actor, upstream, tool, encoded_arguments],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return ResultKey(digest=hashlib.sha256(material.encode("utf-8")).hexdigest())


@dataclass
class _Entry:
    result: CallToolResult
    expires_at: float


class ResultCache:
    """Tool results, held per principal, for as long as the table permits.

    Bounded and least-recently-used, like the credential cache. Deliberately
    *not* single-flight: two concurrent identical calls produce two upstream
    calls. Collapsing them would mean one caller's request being answered by a
    response fetched for another — which is safe here only because the key
    already proves they are the same principal, but it also means a tool with
    side effects that somebody wrongly marked cacheable would have its side
    effect silently skipped for one of them. The credential cache collapses
    concurrent misses because minting a token twice is waste; calling a tool
    twice is behaviour.
    """

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._entries: OrderedDict[ResultKey, _Entry] = OrderedDict()
        self._max_entries = max_entries
        # Monotonic: a wall-clock jump must not extend an entry's life. The
        # quota counter uses wall clock deliberately, because a daily window
        # aligns to real calendar time; a cache lifetime aligns to nothing.
        self._clock = clock or time.monotonic
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: ResultKey) -> CallToolResult | None:
        """A live result for this key, or ``None``.

        Returns a deep copy. The alternative hands every caller a reference to
        one shared model, and `CallToolResult` is mutable — so a caller that
        edits what it was given edits what the next caller receives. A cache
        whose entries change behind it is worse than no cache, because the
        corruption arrives looking like the upstream's own answer.
        """
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() >= entry.expires_at:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry.result.model_copy(deep=True)

    def put(self, key: ResultKey, result: CallToolResult, *, ttl: float) -> None:
        """Store a result, unless it is one that must never be stored.

        **A failed tool call is never cached**, and the check lives here rather
        than at the call site so it cannot be forgotten by a future caller. A
        tool that ran and failed is a fact about one moment — a rate limit
        upstream, a record briefly locked, a transient dependency — and caching
        it converts a blip into a minute of guaranteed failure for everybody who
        shares the key.

        A non-positive TTL stores nothing, so a table entry of zero means "do
        not cache" without needing a second way to say it.
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
