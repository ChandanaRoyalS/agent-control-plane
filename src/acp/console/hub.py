"""Fan one stream of events out to whoever is watching, and never the reverse.

Task 63. The hub sits between the audit write and the browser, and every
decision in it follows from one rule:

**A watcher must not be able to affect the thing it is watching.**

The console is a demo aid. The audit write is the gateway's central guarantee.
If a browser tab left open on a laptop that went to sleep can slow down a
request, or fail one, then a debugging convenience has been given authority over
the request path — which is the shape of an outage caused by a feature nobody
considered load-bearing.

So:

- **`publish` is synchronous, non-blocking, and cannot raise.** It is called
  from `AuditLog.arecord` after the entry is durable. Anything that could
  suspend there would put a browser between a caller and its response.
- **Each subscriber gets a bounded buffer**, and a full one **drops the oldest**
  rather than blocking the publisher or growing without limit. An authenticated
  operator who opens a stream and stops reading is a memory target otherwise.
- **Drops are counted and told to the subscriber that suffered them.** A trace
  console that quietly omits events is worse than no console, because it is
  read as complete. The same argument as reporting an unknown rather than
  guessing it: *when you cannot show something, say that you could not.*

Nothing here is persisted. The chain is the record; this is a window onto it,
and a window that has been closed for an hour has nothing to catch up on. What
it does keep is a short ring of recent events, so a console opened thirty
seconds into a demo is not a blank page — a demo aid that shows nothing until
the next request is a demo aid nobody waits for.
"""

from __future__ import annotations

import asyncio
from collections import deque
from types import TracebackType
from typing import Final, Self

from acp.console.events import TraceEvent

BUFFER: Final = 256
"""Events held per subscriber before the oldest is dropped. Roughly ten seconds
of a busy demo, which is long enough to ride out a browser's paint and short
enough that a forgotten tab costs kilobytes."""

HISTORY: Final = 50
"""Recent events replayed to a new subscriber, so an opened console is not
blank. Deliberately small: this is the last few seconds of context, not a log
viewer, and anything older is a question for `acp audit verify`."""


class Subscription:
    """One watcher's queue, and the count of what it missed.

    An async iterator rather than a callback, because the consumer is an SSE
    response body and `async for` is what that wants — and because a callback
    would run publisher code inside a subscriber's failure.
    """

    def __init__(self, hub: TraceHub, buffer: int = BUFFER) -> None:
        self._hub = hub
        self._events: deque[TraceEvent] = deque(maxlen=buffer)
        self._ready = asyncio.Event()
        self._closed = False
        self.dropped = 0
        """How many events this subscriber never saw, because it was not
        reading fast enough. Surfaced rather than swallowed — see the module."""

    def offer(self, event: TraceEvent) -> None:
        """Take an event, dropping the oldest if this watcher is behind.

        `deque(maxlen=...)` discards silently, so the drop is counted here by
        comparing lengths — the count is the entire point and a `maxlen` that
        quietly ate events would be exactly the failure this class is meant to
        make visible.
        """
        if self._closed:
            return
        if len(self._events) == self._events.maxlen:
            self.dropped += 1
        self._events.append(event)
        self._ready.set()

    def close(self) -> None:
        self._closed = True
        self._events.clear()
        self._ready.set()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> TraceEvent:
        while True:
            if self._events:
                return self._events.popleft()
            if self._closed:
                raise StopAsyncIteration
            self._ready.clear()
            await self._ready.wait()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._hub.unsubscribe(self)


class TraceHub:
    """Every watcher, and the last few events for the one who arrives next."""

    def __init__(self, buffer: int = BUFFER, history: int = HISTORY) -> None:
        self._subscribers: list[Subscription] = []
        self._recent: deque[TraceEvent] = deque(maxlen=history)
        self._buffer = buffer

    @property
    def watchers(self) -> int:
        return len(self._subscribers)

    def publish(self, event: TraceEvent) -> None:
        """Hand an event to every watcher. Never blocks, never raises.

        Iterating a copy of the list, because a subscriber that closes during
        the loop would otherwise mutate it mid-iteration — and the failure would
        appear as an occasional missed event under load, which is the hardest
        kind of bug to see in a thing whose whole job is showing you events.
        """
        self._recent.append(event)
        for subscriber in list(self._subscribers):
            subscriber.offer(event)

    def subscribe(self) -> Subscription:
        """A new watcher, primed with recent history."""
        subscription = Subscription(self, buffer=self._buffer)
        for event in self._recent:
            subscription.offer(event)
        self._subscribers.append(subscription)
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        subscription.close()
        if subscription in self._subscribers:
            self._subscribers.remove(subscription)
