"""Unit tests for the upstream wire models (the parsing direction)."""

from __future__ import annotations

from acp.upstream.models import CallToolResult, ContentBlock, ToolDefinition


def test_tool_definition_parses_the_wire_alias() -> None:
    tool = ToolDefinition.model_validate(
        {"name": "read_document", "description": "d", "inputSchema": {"type": "object"}}
    )

    assert tool.input_schema == {"type": "object"}


def test_tool_definition_tolerates_unknown_fields() -> None:
    """A spec revision adding a field must not break the gateway.

    ``extra="allow"`` here is a deliberate asymmetry with the mocks, which
    forbid extras. Strictness is right for a test fixture that should catch our
    bugs; tolerance is right for a proxy that must not break on someone else's
    perfectly valid additions.
    """
    tool = ToolDefinition.model_validate(
        {"name": "t", "inputSchema": {}, "title": "T", "annotations": {"readOnly": True}}
    )

    assert tool.name == "t"


def test_tool_definition_defaults_missing_optional_fields() -> None:
    tool = ToolDefinition.model_validate({"name": "t"})

    assert tool.description == ""
    assert tool.input_schema == {}


def test_call_tool_result_parses_is_error_alias() -> None:
    result = CallToolResult.model_validate(
        {"content": [{"type": "text", "text": "boom"}], "isError": True}
    )

    assert result.is_error is True
    assert result.text() == "boom"


def test_call_tool_result_defaults_is_error_to_false() -> None:
    assert CallToolResult.model_validate({"content": []}).is_error is False


def test_text_joins_multiple_blocks() -> None:
    result = CallToolResult.model_validate(
        {"content": [{"type": "text", "text": "one"}, {"type": "text", "text": "two"}]}
    )

    assert result.text() == "one\ntwo"


def test_text_ignores_non_text_content() -> None:
    """Image and resource blocks must pass through without breaking text extraction."""
    result = CallToolResult.model_validate(
        {
            "content": [
                {"type": "text", "text": "caption"},
                {"type": "image", "data": "base64...", "mimeType": "image/png"},
            ]
        }
    )

    assert result.text() == "caption"
    assert len(result.content) == 2, "non-text content must be preserved, not dropped"


def test_unknown_content_type_is_preserved() -> None:
    block = ContentBlock.model_validate({"type": "something-new-in-a-later-spec", "foo": "bar"})

    assert block.type == "something-new-in-a-later-spec"
    assert block.text is None
