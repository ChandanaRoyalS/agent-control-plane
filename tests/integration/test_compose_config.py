"""Every tool the shipped config names must be a tool that exists.

**This file exists because a one-character typo shipped.** Task 55's demo policy
said `mock-a__create-ticket`; the tool is `create_ticket`, with an underscore.
The rule was valid YAML, loaded without complaint, passed every schema check —
and matched nothing. First-match-wins then handed the call to the broad `allow`
underneath it, so the composed stack executed the call it was supposed to hold,
and the only symptom was a demo that quietly did not demonstrate anything.

**A misspelt tool name is not a syntax error, it is a silent behaviour change**,
and which direction it fails in depends on the effect:

- in a `deny` rule it is a **hole** — the tool it was meant to stop is now
  governed by whatever matches next;
- in a `require_approval` rule it is a **hole** — exactly what happened here;
- in an `allow` rule it is **dead config**, and the caller is refused by the deny
  default while the file appears to permit them;
- in `costs.yaml` the call is charged the default weight rather than its real one;
- in `cache.yaml` the tool is silently not cacheable, or worse, a write is named
  and never takes effect.

None of those produce an error anywhere. Only a cross-check does.

**Scope: the files that run against the mock fleet, and not the illustrative
ones.** `config/policy.yaml` deliberately names a CRM this repository does not
contain — it is the example of what a real policy looks like, and holding it to
the mocks' catalogue would force it to become a worse example. `policy.compose.yaml`,
`costs.yaml` and `cache.yaml` are different: they are loaded by `make up` against
these exact upstreams, so a name in them is a claim that can be checked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from acp.gateway.naming import qualify
from acp.mocks import mock_a, mock_b

pytestmark = pytest.mark.integration

CONFIG = Path(__file__).resolve().parents[2] / "config"


def catalogue() -> set[str]:
    """Every qualified tool name the composed stack actually serves.

    Built with `qualify` rather than by writing `mock-a__search` out by hand, so
    this cannot drift from the naming rule the gateway applies — the separator,
    the truncation, all of it. A test that spelled the names itself would be a
    second implementation of the thing under test.
    """
    return {
        qualify(upstream, tool.name)
        for upstream, tools in (("mock-a", mock_a.TOOLS), ("mock-b", mock_b.TOOLS))
        for tool in tools
    }


def load(name: str) -> Any:
    return yaml.safe_load((CONFIG / name).read_text())


def policy_tools() -> set[str]:
    document = load("policy.compose.yaml")
    return {tool for rule in document.get("rules", []) for tool in rule.get("tools", []) or []}


# ---------------------------------------------------------------------------


def test_the_catalogue_is_not_empty() -> None:
    """The guard on the guard.

    Every assertion below is a subset check, and a subset of nothing is
    vacuously true for an empty left-hand side — so if `catalogue()` ever
    returned nothing, this whole file would pass while checking nothing at all.
    Lesson 21: a test whose failure can be fixed by deleting data needs a test
    that fails when the data is deleted.
    """
    assert len(catalogue()) == 6


def test_every_tool_the_compose_policy_names_exists() -> None:
    """**The one this file was written for.**

    A rule naming a tool nobody serves does not fail. It never matches, and the
    next rule decides — which for task 55's demo meant the call the policy was
    written to hold ran without anybody being asked.
    """
    unknown = policy_tools() - catalogue()

    assert not unknown, f"policy.compose.yaml names tools the mock fleet does not serve: {unknown}"


def test_the_compose_policy_still_gates_something() -> None:
    """A demo of human-in-the-loop approval that gates nothing is not a demo.

    Asserted separately from the name check because they fail for different
    reasons: this one goes red if somebody removes the rule, and the one above
    goes red if somebody misspells it. Merging them would let a deletion
    masquerade as a pass.
    """
    document = load("policy.compose.yaml")
    gated = [rule for rule in document["rules"] if rule.get("effect") == "require_approval"]

    assert gated, "the composed policy no longer holds any call for a person"
    assert set(gated[0]["tools"]) <= catalogue()


def test_the_gated_rule_comes_before_the_broad_allow() -> None:
    """First match wins (ADR 0026), so order is behaviour, not formatting.

    A `require_approval` rule *below* an unconditional `allow` is unreachable —
    valid, loaded, and dead. That is the same failure as the misspelt name
    arriving by a different route, and it is equally silent.
    """
    effects = [rule.get("effect") for rule in load("policy.compose.yaml")["rules"]]

    assert "require_approval" in effects
    assert effects.index("require_approval") < effects.index("allow")


def test_every_tool_the_cost_table_names_exists() -> None:
    """A misspelt cost is charged the default weight, silently and forever."""
    weights = load("costs.yaml").get("costs", {}) or {}
    unknown = set(weights) - catalogue()

    assert not unknown, f"costs.yaml names tools the mock fleet does not serve: {unknown}"


def test_every_tool_the_cache_table_names_exists() -> None:
    """A misspelt cacheable tool is silently not cached — a performance claim the
    deployment does not actually make."""
    document = load("cache.yaml")
    # A mapping of tool to TTL, so the keys are the names.
    named = set(document.get("tools", {}) or {})
    unknown = named - catalogue()

    assert not unknown, f"cache.yaml names tools the mock fleet does not serve: {unknown}"
