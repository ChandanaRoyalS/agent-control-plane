"""Tests for the error taxonomy.

These look trivial and are not: the JSON-RPC rendering is the contract the agent
sees, so it gets a test from the first commit.
"""

from __future__ import annotations

import pytest

from acp.exceptions import ACPError, ConfigurationError


def test_base_error_renders_jsonrpc() -> None:
    err = ACPError("something went wrong")
    rendered = err.to_jsonrpc_error()

    assert rendered["code"] == -32000
    assert rendered["message"] == "something went wrong"
    assert rendered["data"]["recoverable"] is False


def test_details_are_merged_into_data() -> None:
    err = ACPError("upstream refused", details={"upstream": "mock-a"})
    rendered = err.to_jsonrpc_error()

    assert rendered["data"]["upstream"] == "mock-a"
    assert rendered["data"]["recoverable"] is False


def test_configuration_error_has_its_own_code() -> None:
    err = ConfigurationError("policy file is malformed")

    assert err.code == -32001
    assert isinstance(err, ACPError)
    assert err.to_jsonrpc_error()["code"] == -32001


def test_error_is_raisable_and_carries_message() -> None:
    with pytest.raises(ACPError, match="boom"):
        raise ACPError("boom")


def test_details_default_to_empty_dict() -> None:
    assert ACPError("no details").details == {}
