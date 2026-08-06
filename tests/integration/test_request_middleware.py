"""Integration tests for the ASGI request-context middleware.

Driven through a real ASGI app over ``httpx.ASGITransport`` rather than by
calling ``__call__`` with a hand-built scope. The middleware's job is to behave
correctly as one link in an ASGI chain — wrapping ``send``, passing lifespan
messages through untouched, leaving the response otherwise intact — and a
hand-built scope tests none of that.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from acp.observability import context
from acp.observability.log import ContextFilter, JsonFormatter
from acp.observability.middleware import (
    MAX_INBOUND_ID_LENGTH,
    RequestContextMiddleware,
)

pytestmark = pytest.mark.integration


class BoomError(Exception):
    pass


async def echo_id(_request: Any) -> JSONResponse:
    """Reports the request ID the handler can see, which is the whole point:
    the ID has to be visible to the code doing the work, not just to the
    middleware that created it."""
    return JSONResponse({"request_id": context.request_id(), "context": dict(context.current())})


async def explode(_request: Any) -> PlainTextResponse:
    raise BoomError


def build_app() -> Starlette:
    app = Starlette(routes=[Route("/echo", echo_id), Route("/boom", explode)])
    app.add_middleware(RequestContextMiddleware)
    return app


def get(path: str = "/echo", **kwargs: Any) -> httpx.Response:
    async def _run() -> httpx.Response:
        app = build_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.get(path, **kwargs)

    # Bound to a typed name rather than returned straight from `anyio.run`,
    # which is typed as returning Any.
    response: httpx.Response = anyio.run(_run)
    return response


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def test_every_request_gets_an_id_the_handler_can_see() -> None:
    body = get().json()

    assert body["request_id"]


def test_two_requests_get_different_ids() -> None:
    assert get().json()["request_id"] != get().json()["request_id"]


def test_an_inbound_id_is_adopted() -> None:
    """Keeps a caller's trace intact across the hop into the gateway."""
    response = get(headers={"x-request-id": "caller-supplied"})

    assert response.json()["request_id"] == "caller-supplied"


def test_the_id_is_echoed_back_to_the_client() -> None:
    """So a client can quote an ID in a bug report that can actually be found."""
    response = get()

    assert response.headers["x-request-id"] == response.json()["request_id"]


def test_the_method_and_path_are_bound_for_every_log_line() -> None:
    body = get().json()

    assert body["context"]["method"] == "GET"
    assert body["context"]["path"] == "/echo"


# ---------------------------------------------------------------------------
# An inbound ID is attacker-controlled
# ---------------------------------------------------------------------------


def test_an_oversized_inbound_id_is_replaced() -> None:
    """Unbounded, this is a way to write megabytes into a log aggregator per
    request at no cost to the caller."""
    huge = "x" * (MAX_INBOUND_ID_LENGTH + 1)

    rid = get(headers={"x-request-id": huge}).json()["request_id"]

    assert rid != huge
    assert len(rid) <= MAX_INBOUND_ID_LENGTH


def test_a_non_printable_inbound_id_is_replaced() -> None:
    """The ID is copied onto every log line for this request. A caller that can
    put a newline in it can forge log entries."""
    rid = get(headers={"x-request-id": "abc\tdef"}).json()["request_id"]

    assert "\t" not in rid


def test_an_empty_inbound_id_is_replaced() -> None:
    assert get(headers={"x-request-id": "   "}).json()["request_id"]


# ---------------------------------------------------------------------------
# It must not change the response
# ---------------------------------------------------------------------------


def test_the_response_body_and_status_are_untouched() -> None:
    response = get()

    assert response.status_code == 200
    assert set(response.json()) == {"request_id", "context"}


def test_a_handler_failure_still_propagates() -> None:
    """Middleware that swallows an exception to log it turns a 500 with a stack
    trace into a hang or a blank 200."""
    with pytest.raises(BoomError):
        get("/boom")


# ---------------------------------------------------------------------------
# What it logs
# ---------------------------------------------------------------------------


def test_the_request_is_logged_as_an_event_with_a_duration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="acp.observability.middleware"):
        get()

    entry = next(r for r in caplog.records if r.getMessage() == "http.request")
    assert entry.status == 200  # type: ignore[attr-defined]
    assert entry.duration_ms >= 0  # type: ignore[attr-defined]


def test_a_failure_is_logged_with_its_traceback(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.ERROR, logger="acp.observability.middleware"),
        pytest.raises(BoomError),
    ):
        get("/boom")

    entry = next(r for r in caplog.records if r.getMessage() == "http.request.failed")
    assert entry.exc_info is not None, "without the traceback the log is a notification, not a clue"


def test_the_logged_line_carries_the_request_id() -> None:
    """End to end, through the real pipeline: the ID the client was given is the
    ID in the emitted JSON. This is the only reason any of this is worth
    building.

    Driven through an actual handler rather than by applying the filter to a
    captured record afterwards, because the context is gone by then — the filter
    reads contextvars in the task that logged the line, and that task has since
    finished. Attaching it to the handler is what makes it run at emit time, and
    a test that reaches for the record later would pass against a pipeline
    wired the wrong way round.
    """
    lines: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(self.format(record))

    handler = Capture()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(ContextFilter())
    logger = logging.getLogger("acp.observability.middleware")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    try:
        response = get(headers={"x-request-id": "trace-me"})
    finally:
        logger.removeHandler(handler)

    emitted = [json.loads(line) for line in lines]
    entry = next(e for e in emitted if e["event"] == "http.request")

    assert response.headers["x-request-id"] == "trace-me"
    assert entry["request_id"] == "trace-me"
    assert entry["path"] == "/echo"


# ---------------------------------------------------------------------------
# Non-HTTP scopes
# ---------------------------------------------------------------------------


def test_lifespan_messages_pass_through_untouched() -> None:
    """A lifespan message is not a request and has no ID to correlate. Treating
    it as one is how middleware breaks startup."""
    started = False

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal started
        if scope["type"] == "lifespan":
            started = True

    async def _run() -> None:
        wrapped = RequestContextMiddleware(app)
        await wrapped({"type": "lifespan"}, _noop, _noop)

    async def _noop(*_args: Any, **_kwargs: Any) -> Any:
        return None

    anyio.run(_run)

    assert started is True
