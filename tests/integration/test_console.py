"""The console, through the real admin app — task 63.

The unit tests cover the hub's back-pressure and the wire shape. These cover the
two things only an assembled app can answer: **whether the routes are actually
mounted where they are supposed to be**, and **whether they refuse the people
they are supposed to refuse**.

Both are the kind of thing that passes review and ships broken, because the code
reads correctly at every individual layer.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import anyio
import pytest
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.testclient import TestClient

from acp.admin import build_admin_app
from acp.console.app import CONSOLE_PATH, STREAM_PATH, build_stream
from acp.console.events import Source, TraceEvent
from acp.console.hub import TraceHub

pytestmark = pytest.mark.integration

CREDENTIAL = "operator-token-for-tests"


def an_event(name: str = "policy.denied") -> TraceEvent:
    return TraceEvent(
        source=Source.RECORDED,
        category="authorization",
        event=name,
        at=1.0,
        seq=3,
        subject="alice",
    )


def test_the_console_is_absent_when_no_credential_is_configured() -> None:
    """Absent rather than present and closed, following the operator channel: a
    route that exists and always refuses still tells an unauthenticated caller
    what this deployment runs."""
    client = TestClient(build_admin_app(console=TraceHub(), operator_credential=""))
    assert client.get(CONSOLE_PATH).status_code == 404
    assert client.get(STREAM_PATH).status_code == 404


def test_the_console_is_absent_when_there_is_no_hub() -> None:
    client = TestClient(build_admin_app(console=None, operator_credential=CREDENTIAL))
    assert client.get(CONSOLE_PATH).status_code == 404


def test_the_page_is_served_without_a_credential() -> None:
    """Deliberate: it contains no data, and `fetch` can carry a header where an
    address bar cannot. Gating it would make the console unreachable from a
    browser while protecting markup."""
    client = TestClient(build_admin_app(console=TraceHub(), operator_credential=CREDENTIAL))
    response = client.get(CONSOLE_PATH)
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_the_stream_refuses_without_the_credential() -> None:
    """THE ONE THAT MATTERS. This stream carries every principal's activity, so
    an unauthenticated reader is a cross-principal disclosure of everything the
    gateway is doing."""
    client = TestClient(build_admin_app(console=TraceHub(), operator_credential=CREDENTIAL))
    response = client.get(STREAM_PATH)
    assert response.status_code == 401
    assert "Bearer" in response.headers["www-authenticate"]


def test_the_stream_refuses_the_wrong_credential() -> None:
    client = TestClient(build_admin_app(console=TraceHub(), operator_credential=CREDENTIAL))
    headers = {"Authorization": "Bearer not-the-token"}
    assert client.get(STREAM_PATH, headers=headers).status_code == 401


def test_the_stream_refuses_a_credential_in_the_query_string() -> None:
    """`EventSource` cannot set headers, and the usual workaround is a token in
    the URL — which lands in browser history, referrers and access logs. It is
    not accepted here, so nobody can quietly adopt it."""
    client = TestClient(build_admin_app(console=TraceHub(), operator_credential=CREDENTIAL))
    assert client.get(f"{STREAM_PATH}?token={CREDENTIAL}").status_code == 401


async def _frames(response: StreamingResponse, count: int) -> list[str]:
    """The first `count` frames of a stream that never ends.

    Driven directly rather than through `TestClient`, and that is not a
    shortcut. **The SSE body is an infinite generator**, and `TestClient` has no
    way to cancel one: closing the client-side response does not stop the
    server-side loop, so `with client.stream(...)` blocks on exit forever. The
    first version of these tests hung for two minutes and had to be killed.

    Under a real ASGI server the disconnect cancels the task at the generator's
    next suspension point, which the keepalive guarantees arrives within
    `KEEPALIVE_SECONDS`. That is a property of uvicorn, not of the test client,
    and the project's own rule applies: when the harness cannot run it, drive
    the app directly.
    """
    collected: list[str] = []
    with anyio.move_on_after(2.0):
        async for chunk in response.body_iterator:
            # `body_iterator` is typed as yielding `str | bytes`; this endpoint
            # yields `str`. Decoded rather than cast, so a future change that
            # starts yielding bytes is handled instead of silently wrong.
            collected.append(chunk if isinstance(chunk, str) else bytes(chunk).decode())
            if len(collected) >= count:
                break
    return collected


def _request(credential: str | None) -> Request:
    headers = [(b"authorization", f"Bearer {credential}".encode())] if credential else []
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": STREAM_PATH,
            "headers": headers,
            "query_string": b"",
        }
    )


def test_a_watcher_receives_what_was_published_before_it_connected() -> None:
    """The history ring. A console opened thirty seconds into a demo must not be
    a blank page until the next request."""
    hub = TraceHub()
    hub.publish(an_event("policy.allowed"))
    endpoint = build_stream(hub, CREDENTIAL)

    async def run() -> list[str]:
        response = await endpoint(_request(CREDENTIAL))
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-store"
        # A live stream behind an nginx default is a batch delivered when the
        # buffer fills, which is the same as a broken console for a demo.
        assert response.headers["x-accel-buffering"] == "no"
        return await _frames(response, 2)

    frames = anyio.run(run)
    assert frames[0] == ": connected\n\n"
    payload = json.loads(frames[1].split("data: ", 1)[1].strip())
    assert payload["event"] == "policy.allowed"
    assert payload["source"] == "recorded"
    assert payload["seq"] == 3


def test_a_watcher_receives_what_is_published_after_it_connects() -> None:
    """The other half, and the one that would break silently: a console that
    only ever replayed history would look perfect for the first second."""
    hub = TraceHub()
    endpoint = build_stream(hub, CREDENTIAL)

    async def run() -> list[str]:
        response = await endpoint(_request(CREDENTIAL))
        async with anyio.create_task_group() as group:
            collected: list[str] = []

            async def read() -> None:
                collected.extend(await _frames(response, 2))

            group.start_soon(read)
            await anyio.sleep(0.05)
            hub.publish(an_event("firewall.withheld"))
        return collected

    frames = anyio.run(run)
    payload = json.loads(frames[1].split("data: ", 1)[1].strip())
    assert payload["event"] == "firewall.withheld"


def test_the_watcher_is_unsubscribed_when_the_stream_ends() -> None:
    """Otherwise every closed browser tab leaves a subscriber attached to the
    hub, receiving events forever — a slow leak that only shows up after a
    demo has been run a few dozen times."""
    hub = TraceHub()
    hub.publish(an_event())
    endpoint = build_stream(hub, CREDENTIAL)

    async def run() -> None:
        response = await endpoint(_request(CREDENTIAL))
        await _frames(response, 2)
        assert hub.watchers == 1
        await response.body_iterator.aclose()

    anyio.run(run)
    assert hub.watchers == 0


def test_only_the_admin_app_can_mount_the_console() -> None:
    """The security property, bounded statically rather than sampled.

    An agent addresses the gateway. If these routes were ever mounted there, an
    agent could read what every other principal is doing — ADR 0049's argument
    in task 63's clothes.

    A static check on *who imports the mounting function* rather than a request
    against an assembled gateway app, for the reason lesson 10 gives: bounding
    which code can reach a thing beats any number of tests on what that code
    does with it. A behavioural test passes for the app it happened to build;
    this one fails the moment anybody wires the console anywhere else."""
    root = Path(__file__).resolve().parents[2] / "src" / "acp"
    defining = root / "console" / "app.py"

    importers = set()
    for path in root.rglob("*.py"):
        if path == defining:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "console_routes" for alias in node.names
            ):
                importers.add(path.relative_to(root).as_posix())

    # Parsed rather than grepped, and the first version was grepped and failed:
    # `runtime.py` MENTIONS `console_routes` in a comment explaining why the hub
    # is built unconditionally, and a text search cannot tell an explanation
    # from a wiring. Excluding the defining module by filename was the second
    # bug in the same three lines — `app.py` is not a unique name.
    assert importers == {"admin.py"}, f"console_routes imported by {sorted(importers)}"
