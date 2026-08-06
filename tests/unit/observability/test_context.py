"""Unit tests for request-scoped context.

The isolation properties are the reason this uses ``contextvars`` at all, and
they are exactly the properties that are invisible until two agents are
connected at once and log lines start attributing one request's work to another.
So they are tested with genuinely concurrent tasks rather than by inspection.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from acp.observability import context


@pytest.fixture(autouse=True)
def _clean_context() -> Any:
    context.clear()
    yield
    context.clear()


def run(fn: Any) -> Any:
    return anyio.run(fn)


def test_ids_are_unique_across_calls() -> None:
    """A counter would restart at zero on every deploy, so two processes in a
    replica set produce colliding IDs and a search returns two unrelated
    requests interleaved."""
    ids = {context.new_request_id() for _ in range(1000)}

    assert len(ids) == 1000


def test_a_request_scope_supplies_an_id() -> None:
    with context.request() as rid:
        assert context.request_id() == rid


def test_an_inbound_id_is_honoured() -> None:
    """The gateway sits behind other services. Generating a fresh ID would break
    the trace at precisely the boundary where following it matters most."""
    with context.request("from-the-caller") as rid:
        assert rid == "from-the-caller"
        assert context.request_id() == "from-the-caller"


def test_context_is_restored_on_the_way_out() -> None:
    with context.context(a=1):
        with context.context(a=2, b=3):
            assert context.current()["a"] == 2
        assert context.current()["a"] == 1, "the inner scope must not survive its block"
        assert "b" not in context.current()

    assert context.current() == {}


def test_bind_adds_to_the_current_scope() -> None:
    """For facts discovered part-way through — the resolved upstream, or the
    principal once authenticated in task 22."""
    with context.request("req-1"):
        context.bind(upstream="mock-a")

        assert context.current() == {"request_id": "req-1", "upstream": "mock-a"}


def test_outside_a_request_there_is_no_id() -> None:
    assert context.request_id() is None
    assert context.current() == {}


# ---------------------------------------------------------------------------
# The isolation properties — the reason for contextvars over a global
# ---------------------------------------------------------------------------


def test_concurrent_tasks_do_not_see_each_others_ids() -> None:
    """The failure this prevents: two agents connected at once, and log lines
    attributing one request's upstream calls to the other's ID."""
    seen: dict[str, str | None] = {}

    async def handler(name: str) -> None:
        with context.request(f"req-{name}"):
            # Yield control mid-request, so the tasks genuinely interleave
            # rather than running to completion one after another.
            await anyio.sleep(0.01)
            seen[name] = context.request_id()

    async def _run() -> None:
        async with anyio.create_task_group() as tg:
            for name in ("a", "b", "c"):
                tg.start_soon(handler, name)

    run(_run)

    assert seen == {"a": "req-a", "b": "req-b", "c": "req-c"}


def test_a_child_task_inherits_the_request_it_was_started_from() -> None:
    """What makes this usable for a gateway at all: `list_tools` fans out to
    every upstream in a task group, and each of those tasks has to log under the
    request that caused them."""
    seen: list[str | None] = []

    async def fan_out() -> None:
        seen.append(context.request_id())

    async def _run() -> None:
        with context.request("req-1"):
            async with anyio.create_task_group() as tg:
                for _ in range(3):
                    tg.start_soon(fan_out)

    run(_run)

    assert seen == ["req-1", "req-1", "req-1"]


def test_a_child_binding_does_not_leak_back_to_the_parent() -> None:
    """Inheritance is a copy, not a share. Otherwise the upstream a fan-out task
    happened to finish last would end up labelling the parent's summary line."""
    parent_after: dict[str, Any] = {}

    async def child(name: str) -> None:
        context.bind(upstream=name)

    async def _run() -> None:
        with context.request("req-1"):
            async with anyio.create_task_group() as tg:
                tg.start_soon(child, "mock-a")
                tg.start_soon(child, "mock-b")
            parent_after.update(context.current())

    run(_run)

    assert parent_after == {"request_id": "req-1"}


def test_the_context_mapping_cannot_be_mutated_in_place() -> None:
    """A `ContextVar` holding a mutable dict looks like it works and quietly
    shares state between tasks, because what gets copied is the reference."""
    with context.request("req-1"):
        current = context.current()

        with pytest.raises(TypeError):
            current["injected"] = True  # type: ignore[index]
