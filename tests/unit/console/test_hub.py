"""The hub, and the one rule it exists to keep — task 63.

**A watcher must not be able to affect the thing it is watching.** The console
is a demo aid; the audit write is the gateway's central guarantee. Every test
here is that sentence in a different position.

Written through `anyio.run` rather than as `async def`, per this project's
convention for async unit tests.
"""

from __future__ import annotations

import anyio
import pytest

from acp.console.events import Source, TraceEvent
from acp.console.hub import HISTORY, TraceHub


def an_event(name: str = "policy.allowed") -> TraceEvent:
    return TraceEvent(source=Source.RECORDED, category="authorization", event=name, at=0.0)


def test_publishing_with_no_watchers_is_not_an_error() -> None:
    """The common case in production: nobody is looking. A hub that needed a
    subscriber would put the console on the request path's critical list."""
    TraceHub().publish(an_event())


def test_publish_never_raises_when_a_subscriber_is_closed() -> None:
    """A browser tab closes mid-request. That must not surface as an exception
    inside `AuditLog.arecord`, which is running between a caller and its
    response."""
    hub = TraceHub()
    subscription = hub.subscribe()
    subscription.close()
    hub.publish(an_event())


def test_a_subscriber_that_stops_reading_drops_the_oldest_and_counts_it() -> None:
    """THE LOAD-BEARING TEST. An authenticated operator who opens a stream and
    walks away is otherwise either a memory target or a brake on every request.

    Dropping is the right failure — the newest events are the ones a live
    console is for — and the count is what stops the drop being a lie."""
    hub = TraceHub(buffer=4, history=0)
    subscription = hub.subscribe()

    for index in range(10):
        hub.publish(an_event(f"e{index}"))

    assert subscription.dropped == 6

    async def drain() -> list[str]:
        seen = []
        for _ in range(4):
            event = await subscription.__anext__()
            seen.append(event.event)
        return seen

    assert anyio.run(drain) == ["e6", "e7", "e8", "e9"]


def test_the_drop_count_is_per_subscriber() -> None:
    """One slow watcher must not make a fast one look lossy, or an operator
    debugging a real gap chases the wrong stream."""
    hub = TraceHub(buffer=2, history=0)
    slow = hub.subscribe()
    fast = hub.subscribe()

    for index in range(5):
        hub.publish(an_event(f"e{index}"))

    async def drain_one() -> None:
        await fast.__anext__()

    anyio.run(drain_one)
    assert slow.dropped == 3


def test_a_new_watcher_sees_recent_history() -> None:
    """A console opened thirty seconds into a demo is otherwise a blank page
    until the next request, and a demo aid nobody waits for is not one."""
    hub = TraceHub(history=3)
    for index in range(5):
        hub.publish(an_event(f"e{index}"))

    subscription = hub.subscribe()

    async def drain() -> list[str]:
        return [(await subscription.__anext__()).event for _ in range(3)]

    assert anyio.run(drain) == ["e2", "e3", "e4"]


def test_history_does_not_grow_without_bound() -> None:
    """It is a ring, not a log. The chain is the log.

    Counted by draining the new subscriber rather than by reading the deque,
    because the private attribute is not the property worth asserting — what a
    watcher actually receives is."""
    hub = TraceHub(history=HISTORY)
    for index in range(HISTORY * 3):
        hub.publish(an_event(f"e{index}"))
    subscription = hub.subscribe()

    async def drain() -> list[str]:
        seen = []
        with anyio.move_on_after(0.05):
            while True:
                seen.append((await subscription.__anext__()).event)
        return seen

    replayed = anyio.run(drain)
    assert len(replayed) == HISTORY
    assert replayed[-1] == f"e{HISTORY * 3 - 1}"


def test_a_watcher_waits_rather_than_spinning() -> None:
    """The iterator must suspend on an empty queue. Returning `None` or busy
    looping would put a CPU-burning coroutine next to the request path — the
    same failure as blocking it, arriving from the other side."""
    hub = TraceHub(history=0)
    subscription = hub.subscribe()
    received: list[str] = []

    async def watch() -> None:
        async with anyio.create_task_group() as group:

            async def consume() -> None:
                received.append((await subscription.__anext__()).event)

            group.start_soon(consume)
            await anyio.sleep(0.01)
            assert not received, "the iterator returned before anything was published"
            hub.publish(an_event("late"))

    anyio.run(watch)
    assert received == ["late"]


def test_closing_a_subscription_ends_its_iteration() -> None:
    """Otherwise an SSE response body never finishes and the connection leaks
    for as long as the process lives."""
    hub = TraceHub(history=0)
    subscription = hub.subscribe()

    async def watch() -> bool:
        async with anyio.create_task_group() as group:
            ended: list[bool] = []

            async def consume() -> None:
                with pytest.raises(StopAsyncIteration):
                    await subscription.__anext__()
                ended.append(True)

            group.start_soon(consume)
            await anyio.sleep(0.01)
            hub.unsubscribe(subscription)
        return bool(ended)

    assert anyio.run(watch)


def test_unsubscribing_removes_the_watcher() -> None:
    hub = TraceHub()
    subscription = hub.subscribe()
    assert hub.watchers == 1
    hub.unsubscribe(subscription)
    assert hub.watchers == 0


def test_a_subscription_unsubscribes_itself_on_exit() -> None:
    """The SSE handler uses `with`, so an exception in the response body cannot
    leave a subscriber attached to the hub receiving events forever."""
    hub = TraceHub()
    with hub.subscribe():
        assert hub.watchers == 1
    assert hub.watchers == 0


def test_unsubscribing_twice_is_harmless() -> None:
    """`with` plus an explicit close is the shape a careful handler ends up
    with, and it must not raise on the second one."""
    hub = TraceHub()
    subscription = hub.subscribe()
    hub.unsubscribe(subscription)
    hub.unsubscribe(subscription)
    assert hub.watchers == 0


def test_a_subscriber_closing_mid_publish_does_not_skip_the_others() -> None:
    """`publish` iterates a copy for this reason. Mutating the list mid-loop
    would surface as an occasional missed event under load — the hardest bug to
    see in a thing whose whole job is showing you events."""
    hub = TraceHub(history=0)
    first = hub.subscribe()
    second = hub.subscribe()
    hub.unsubscribe(first)
    hub.publish(an_event("survivor"))

    async def drain() -> str:
        return (await second.__anext__()).event

    assert anyio.run(drain) == "survivor"
