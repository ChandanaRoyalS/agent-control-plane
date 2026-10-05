"""Fan audit events out to watchers; a watcher can never affect the request path.

`publish` is synchronous, non-blocking and cannot raise; `AuditLog.arecord` calls
it after the entry is durable. Each subscriber has a bounded buffer that drops the
oldest event, and drops are counted and reported to that subscriber. Nothing is
persisted beyond a short ring of recent events replayed to new watchers.
"""

from __future__ import annotations

import asyncio
from collections import deque
from types import TracebackType
from typing import Final, Self

from acp.console.events import TraceEvent

BUFFER: Final = 256
"""Events held per subscriber before the oldest is dropped."""

HISTORY: Final = 50
"""Recent events replayed to a new subscriber; older ones are for `acp audit verify`."""


class Subscription:
    """One watcher's queue, and the count of what it missed.

    An async iterator, not a callback, so no subscriber code runs inside `publish`.
    """

    def __init__(self, hub: TraceHub, buffer: int = BUFFER) -> None:
        self._hub = hub
        self._events: deque[TraceEvent] = deque(maxlen=buffer)
        self._ready = asyncio.Event()
        self._closed = False
        self.dropped = 0
        """Events this subscriber missed by reading too slowly."""

    def offer(self, event: TraceEvent) -> None:
        """Take an event, dropping and counting the oldest if this watcher is behind.

        Counted here because `deque(maxlen=...)` discards silently.
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

        Iterates a copy, since a subscriber may unsubscribe during the loop.
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
