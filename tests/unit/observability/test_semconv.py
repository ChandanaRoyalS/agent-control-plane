"""Unit tests for the MCP span conventions.

Pure data, so these are cheap — and worth having anyway, because a misspelled
attribute name does not fail. It produces a span that silently refuses to group
with every other span in the system, which is discovered weeks later by someone
wondering why a dashboard is empty.
"""

from __future__ import annotations

import pytest

from acp.observability import semconv

# ---------------------------------------------------------------------------
# Span naming
# ---------------------------------------------------------------------------


def test_a_span_with_a_target_names_it() -> None:
    assert semconv.span_name("tools/call", "mock-a__search") == "tools/call mock-a__search"


def test_a_span_without_a_target_is_just_the_method() -> None:
    assert semconv.span_name("tools/list") == "tools/list"


def test_the_span_name_never_contains_arguments() -> None:
    """The convention names a low-cardinality span deliberately. A span name
    built from user input destroys a tracing backend's index."""
    name = semconv.span_name("tools/call", "search")

    assert name == "tools/call search"


# ---------------------------------------------------------------------------
# Client spans
# ---------------------------------------------------------------------------


def client(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "method": "tools/list",
        "upstream": "mock-a",
        "url": "http://127.0.0.1:9101/mcp",
    }
    return semconv.client_attributes(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_a_client_span_always_names_the_method() -> None:
    """The one required attribute."""
    assert client()[semconv.MCP_METHOD_NAME] == "tools/list"


def test_a_client_span_identifies_the_upstream_by_name() -> None:
    """`server.address` carries the host, but two upstreams behind one host
    would be indistinguishable — and "which upstream" is how every dashboard in
    this system slices."""
    assert client()[semconv.ACP_UPSTREAM] == "mock-a"


def test_the_endpoint_is_split_into_host_and_port() -> None:
    attributes = client(url="https://tools.internal:8443/mcp")

    assert attributes[semconv.SERVER_ADDRESS] == "tools.internal"
    assert attributes[semconv.SERVER_PORT] == 8443


@pytest.mark.parametrize(("url", "port"), [("http://host/mcp", 80), ("https://host/mcp", 443)])
def test_a_missing_port_is_filled_in_from_the_scheme(url: str, port: int) -> None:
    """A span that sometimes carries a port and sometimes does not cannot be
    grouped by one."""
    assert client(url=url)[semconv.SERVER_PORT] == port


def test_a_tool_call_is_a_genai_execute_tool_operation() -> None:
    """What makes these traces legible to agent-observability tooling rather
    than only to something that already understands MCP."""
    attributes = client(method="tools/call", tool="search")

    assert attributes[semconv.GEN_AI_OPERATION_NAME] == semconv.EXECUTE_TOOL
    assert attributes[semconv.GEN_AI_TOOL_NAME] == "search"


def test_a_catalogue_fetch_is_not_a_tool_execution() -> None:
    """`tools/list` runs no tool, so claiming an execute_tool operation would
    inflate every count of how many tools the system ran."""
    attributes = client()

    assert semconv.GEN_AI_OPERATION_NAME not in attributes
    assert semconv.GEN_AI_TOOL_NAME not in attributes


def test_the_request_id_is_recorded_as_a_string() -> None:
    """The convention types it as a string. A backend receiving both an int and
    a string for one attribute cannot filter on it."""
    assert client(request_id=7)[semconv.JSONRPC_REQUEST_ID] == "7"


def test_no_arguments_are_ever_recorded() -> None:
    """The load-bearing privacy assertion for this module.

    `gen_ai.tool.call.arguments` is opt-in in the conventions for good reason:
    tool arguments routinely contain queries, identifiers, personal data and
    occasionally credentials, and a span goes somewhere with a different
    retention policy and a different audience than the gateway's own logs.
    Nothing here can put them in a span.
    """
    attributes = client(method="tools/call", tool="search")

    assert semconv.GEN_AI_TOOL_CALL_ARGUMENTS not in attributes
    assert semconv.GEN_AI_TOOL_CALL_RESULT not in attributes


# ---------------------------------------------------------------------------
# Server spans
# ---------------------------------------------------------------------------


def test_a_server_span_carries_the_qualified_tool_name() -> None:
    """The name the *agent* used. The real upstream name appears on the client
    span beneath it, which makes the gateway's renaming visible in the trace
    rather than being something the reader has to already know."""
    attributes = semconv.server_attributes(method="tools/call", tool="mock-a__search")

    assert attributes[semconv.GEN_AI_TOOL_NAME] == "mock-a__search"
    assert attributes[semconv.GEN_AI_OPERATION_NAME] == semconv.EXECUTE_TOOL


def test_a_server_span_does_not_claim_an_endpoint() -> None:
    """`server.address` on an inbound span would describe the gateway talking
    to itself."""
    attributes = semconv.server_attributes(method="tools/list")

    assert semconv.SERVER_ADDRESS not in attributes
    assert semconv.ACP_UPSTREAM not in attributes


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_an_error_is_recorded_by_type_not_by_message() -> None:
    """A message is unbounded and often contains the very values that should
    not be in telemetry. A class name is a small closed set that can be grouped
    and alerted on, which is the whole point of the attribute."""
    attributes = semconv.error_attributes(ValueError("connection to 10.1.2.3 as admin failed"))

    assert attributes[semconv.ERROR_TYPE] == "ValueError"
    assert "admin" not in str(attributes)


def test_a_jsonrpc_error_code_is_recorded_when_there_is_one() -> None:
    attributes = semconv.error_attributes(ValueError("nope"), status_code=-32011)

    assert attributes[semconv.RPC_RESPONSE_STATUS_CODE] == "-32011"


def test_a_failure_with_no_protocol_code_omits_it() -> None:
    """A timeout never reached the upstream, so there is no response code to
    report and inventing one would be a lie a dashboard would believe."""
    assert semconv.RPC_RESPONSE_STATUS_CODE not in semconv.error_attributes(TimeoutError())


# ---------------------------------------------------------------------------
# Naming an outbound span so a fan-out can be read (task 21)
# ---------------------------------------------------------------------------


def test_a_fan_out_produces_distinguishable_span_names() -> None:
    """The failure this exists to prevent, stated as the thing it prevents.

    One `tools/list` becomes a concurrent call to every upstream. Named by
    method alone, all of those spans read identically, and the trace that is
    supposed to show *which upstream was slow* shows three bars nobody can tell
    apart. Found by looking at a real trace in Jaeger — "the labels are
    ambiguous" is not a property a test knows to assert on its own.
    """
    names = {
        semconv.span_name("tools/list", semconv.client_target(upstream))
        for upstream in ("mock-a", "mock-b")
    }

    assert names == {"tools/list mock-a", "tools/list mock-b"}


def test_the_same_tool_on_two_upstreams_is_still_distinguishable() -> None:
    """`search` exists on both mocks (ADR 0003 is why qualification exists at
    all). Naming a client span by tool alone would collapse them too."""
    names = {
        semconv.span_name("tools/call", semconv.client_target(upstream, "search"))
        for upstream in ("mock-a", "mock-b")
    }

    assert names == {"tools/call mock-a/search", "tools/call mock-b/search"}


def test_the_client_span_names_the_tool_that_actually_went_upstream() -> None:
    """Not the qualified name. The agent asked for `mock-a__read_document`; what
    crossed the wire was `read_document`, and a span claiming otherwise would
    describe a request that was never made."""
    name = semconv.span_name("tools/call", semconv.client_target("mock-a", "read_document"))

    assert name == "tools/call mock-a/read_document"
    assert "__" not in name


def test_span_names_stay_bounded() -> None:
    """Both halves come from things the gateway controls — the config file and a
    catalogue — never from the caller. A span name built from caller input is
    how a tracing backend's index gets destroyed."""
    assert semconv.client_target("mock-a") == "mock-a"
    assert semconv.client_target("mock-a", None) == "mock-a"
