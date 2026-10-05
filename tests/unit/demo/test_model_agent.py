"""The model-driven agent's loop and its Ollama transport, with no model.

The loop is tested with a scripted `ChatModel` and a fake `Caller`; the
transport with `httpx.MockTransport`, asserting the request Ollama receives
and parsing the shapes small models actually emit. Whether a real model is
persuaded is not a unit-test question — that is what the recorder measures.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import httpx
import pytest

from acp.demo.model_agent import (
    MAX_OBSERVATION_CHARS,
    Kind,
    Observation,
    OllamaChat,
    Reply,
    Tool,
    ToolCall,
    ollama_tools,
    parse_reply,
    run_agent,
)

pytestmark = pytest.mark.anyio

TOOLS = [Tool("mock-a__search", "Search.", {"type": "object", "properties": {}})]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Script:
    """A model that replies from a list, and remembers what it was shown."""

    def __init__(self, *replies: Reply) -> None:
        self._replies = list(replies)
        self.seen: list[list[Mapping[str, Any]]] = []

    async def chat(self, messages: Sequence[Mapping[str, Any]], tools: Sequence[Tool]) -> Reply:
        self.seen.append(list(messages))
        return self._replies.pop(0)


class Fake:
    def __init__(self, observation: Observation) -> None:
        self.observation = observation
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    async def tools(self) -> list[Tool]:
        return TOOLS

    async def call(self, name: str, arguments: Mapping[str, Any]) -> Observation:
        self.calls.append((name, arguments))
        return self.observation


async def test_the_loop_ends_when_the_model_answers_in_prose() -> None:
    model = Script(Reply("done"))
    transcript = await run_agent(model, Fake(Observation(Kind.SERVED, "x")), "task")
    assert transcript.answer == "done"
    assert transcript.steps == []
    assert transcript.turns == 1


async def test_each_call_is_made_and_its_result_shown_to_the_model() -> None:
    model = Script(Reply("", (ToolCall("mock-a__search", {"query": "q"}),)), Reply("done"))
    caller = Fake(Observation(Kind.SERVED, "found it"))

    transcript = await run_agent(model, caller, "task")

    assert caller.calls == [("mock-a__search", {"query": "q"})]
    assert [s.tool for s in transcript.steps] == ["mock-a__search"]
    shown = model.seen[1][-1]
    assert shown == {"role": "tool", "tool_name": "mock-a__search", "content": "found it"}


async def test_a_refusal_is_shown_as_a_refusal_not_as_a_result() -> None:
    model = Script(Reply("", (ToolCall("mock-a__search", {}),)), Reply("ok"))
    refused = Observation(Kind.REFUSED, "this call was not permitted", code=-32040)

    await run_agent(model, Fake(refused), "task")

    assert model.seen[1][-1]["content"] == (
        "The call was refused (code -32040): this call was not permitted"
    )


async def test_a_hold_says_the_call_did_not_run() -> None:
    assert "has not run" in Observation(Kind.HELD, "").for_model()


async def test_the_model_is_shown_a_bounded_result() -> None:
    long = Observation(Kind.SERVED, "x" * (MAX_OBSERVATION_CHARS * 2))
    assert len(long.for_model()) == MAX_OBSERVATION_CHARS


async def test_the_loop_stops_at_the_step_ceiling() -> None:
    call = Reply("", (ToolCall("mock-a__search", {}),))
    model = Script(*[call] * 3)
    transcript = await run_agent(model, Fake(Observation(Kind.SERVED, "")), "t", max_steps=3)
    assert transcript.turns == 3
    assert transcript.calls == 3
    assert transcript.answer == ""


def test_the_catalogue_is_offered_as_functions() -> None:
    [offered] = ollama_tools(TOOLS)
    assert offered == {
        "type": "function",
        "function": {
            "name": "mock-a__search",
            "description": "Search.",
            "parameters": {"type": "object", "properties": {}},
        },
    }


def test_a_tool_without_a_schema_still_has_object_parameters() -> None:
    [offered] = ollama_tools([Tool("t", "", {})])
    assert offered["function"]["parameters"] == {"type": "object", "properties": {}}


@pytest.mark.parametrize(
    "arguments",
    [{"path": "a.md"}, json.dumps({"path": "a.md"})],
    ids=["object", "json-string"],
)
def test_arguments_are_read_as_an_object_or_a_json_string(arguments: object) -> None:
    payload = {
        "message": {
            "content": "",
            "tool_calls": [{"function": {"name": "mock-a__read_document", "arguments": arguments}}],
        }
    }
    assert parse_reply(payload).calls == (ToolCall("mock-a__read_document", {"path": "a.md"}),)


@pytest.mark.parametrize(
    "raw",
    [
        "not a call",
        {"function": "nope"},
        {"function": {"name": "", "arguments": {}}},
        {"function": {"name": "t", "arguments": "{not json"}},
        {"function": {"name": "t", "arguments": ["a"]}},
    ],
)
def test_a_malformed_call_is_dropped_not_guessed(raw: object) -> None:
    assert parse_reply({"message": {"content": "x", "tool_calls": [raw]}}).calls == ()


def test_a_response_without_a_message_is_an_empty_reply() -> None:
    assert parse_reply({}) == Reply(content="")
    assert parse_reply({"message": {"content": 3}}) == Reply(content="")


async def test_ollama_receives_the_model_tools_and_sampling_options() -> None:
    sent: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat"
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "hi"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        chat = OllamaChat(http, model="m", endpoint="http://ollama/", temperature=0.5, seed=7)
        reply = await chat.chat([{"role": "user", "content": "q"}], TOOLS)

    assert reply == Reply(content="hi")
    [body] = sent
    assert body["model"] == "m"
    assert body["stream"] is False
    assert body["options"] == {"temperature": 0.5, "seed": 7}
    assert body["tools"] == ollama_tools(TOOLS)


async def test_an_ollama_error_fails_the_trial() -> None:
    def handle(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model not found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        with pytest.raises(httpx.HTTPStatusError):
            await OllamaChat(http).chat([], TOOLS)


# ---------------------------------------------------------------------------
# Calls written into the prose (the first llama3.2 run)
# ---------------------------------------------------------------------------

OFFERED = frozenset({"mock-a__read_document", "mock-a__create_ticket"})


def written(content: str) -> Reply:
    return parse_reply({"message": {"role": "assistant", "content": content}}, OFFERED)


def test_a_call_written_as_json_in_the_reply_is_a_call() -> None:
    reply = written(
        'Next I will read it. {"name": "mock-a__read_document", '
        '"parameters": {"path": "hr/compensation-2026.md"}}'
    )
    assert reply.calls == (
        ToolCall("mock-a__read_document", {"path": "hr/compensation-2026.md"}, from_text=True),
    )


def test_fenced_lists_and_function_wrappers_are_read() -> None:
    reply = written(
        "```json\n"
        '[{"name": "mock-a__read_document", "arguments": "{\\"path\\": \\"a.md\\"}"},'
        ' {"function": {"name": "mock-a__create_ticket", "parameters": {"title": "t"}}}]\n'
        "```"
    )
    assert [(c.name, c.arguments) for c in reply.calls] == [
        ("mock-a__read_document", {"path": "a.md"}),
        ("mock-a__create_ticket", {"title": "t"}),
    ]


def test_json_naming_a_tool_that_was_not_offered_is_not_a_call() -> None:
    assert written('{"name": "mock-a__delete_everything", "parameters": {}}').calls == ()


def test_prose_with_unrelated_json_is_not_a_call() -> None:
    assert written('The config was {"retries": 3} and [1, 2] and {broken').calls == ()


def test_the_tool_call_field_wins_over_the_prose() -> None:
    payload = {
        "message": {
            "content": '{"name": "mock-a__create_ticket", "parameters": {"title": "x"}}',
            "tool_calls": [{"function": {"name": "mock-a__read_document", "arguments": {}}}],
        }
    }
    [call] = parse_reply(payload, OFFERED).calls
    assert call == ToolCall("mock-a__read_document", {})


async def test_a_written_call_is_made_and_kept_marked() -> None:
    model = Script(
        Reply("", (ToolCall("mock-a__search", {}, from_text=True),)),
        Reply("done"),
    )
    transcript = await run_agent(model, Fake(Observation(Kind.SERVED, "")), "task")
    assert transcript.steps[0].from_text


async def test_ollama_chat_reads_written_calls_for_offered_tools() -> None:
    def handle(_: httpx.Request) -> httpx.Response:
        content = '{"name": "mock-a__search", "parameters": {"query": "q"}}'
        return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        reply = await OllamaChat(http).chat([], TOOLS)

    assert reply.calls == (ToolCall("mock-a__search", {"query": "q"}, from_text=True),)
