"""Unit tests for the per-tool cost table."""

from __future__ import annotations

from acp.budget import CostTable


def test_a_listed_tool_costs_what_the_table_says() -> None:
    table = CostTable(costs={"mock-a__search": 5.0})
    assert table.cost_of("mock-a__search") == 5.0


def test_an_unlisted_tool_costs_the_default() -> None:
    table = CostTable(costs={"mock-a__search": 5.0}, default=2.0)
    assert table.cost_of("mock-b__summarize") == 2.0


def test_the_default_default_is_one() -> None:
    """An empty table charges one per call — exactly task 38's behaviour, so
    turning cost accounting on with no costs configured changes nothing."""
    assert CostTable().cost_of("anything") == 1.0


def test_a_zero_cost_is_a_free_call() -> None:
    """Zero is a deliberate choice for a cheap tool, not an error."""
    table = CostTable(costs={"mock-a__ping": 0.0})
    assert table.cost_of("mock-a__ping") == 0.0
