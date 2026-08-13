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

import enum
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from acp.config import GatewaySettings
from acp.gateway.naming import qualify
from acp.mocks import mock_a, mock_b

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
COMPOSE = ROOT / "docker-compose.yml"


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


# ---------------------------------------------------------------------------
# A control nobody runs is a control that does not exist
# ---------------------------------------------------------------------------
#
# THIS SECTION EXISTS BECAUSE THE SAME BUG SHIPPED SIX TIMES.
#
# Every one of them had the same shape: a feature built, tested, merged — and
# switched off in the only deployment anybody runs, because nothing set its
# environment variable. `scripts/patch_compose_firewall.py` fixed four at once
# (cost table, result cache, provenance framing, the firewall). Task 62's
# overhead register then found two more, and the sixth was the most complete:
# `ACP_COST_FILE` was set while `ACP_RATE_LIMIT_ENABLED` and `ACP_QUOTA_ENABLED`
# were not, so `config/costs.yaml` was parsed at every start to feed a decision
# `_charge` never reached.
#
# None of those produce an error. The gateway starts, serves, and is quietly a
# smaller system than the repository describes.
#
# So the check is derived from `GatewaySettings` rather than written out by
# hand: **anything that defaults to off must be either wired into compose or
# named below with a reason.** A new optional feature fails this test until
# somebody decides which it is, and that is the point — the decision is the
# thing that kept getting skipped.

DELIBERATELY_OFF = {
    "ACP_TENANT_POLICY_DIR": (
        "the composed demo runs one Keycloak realm, so there are no tenant "
        "labels and no per-tenant policy files to point at (ADR 0051's stated "
        "cut). A second realm would turn multi-tenancy from tested into "
        "demonstrable, and is listed as a gap rather than done."
    ),
    "ACP_FIREWALL_CLASSIFIER_ENABLED": (
        "it calls a model over Ollama, which the compose stack does not run and "
        "will not download. ADR 0042 makes the classifier optional precisely so "
        "the firewall's measured numbers come from the deterministic detectors."
    ),
    "ACP_AUTH_ISSUERS_FILE": (
        "the demo uses the single-issuer settings above (ACP_AUTH_ISSUER and "
        "friends). The issuers file is the multi-issuer path, and configuring "
        "both would leave two answers to the question of who is trusted."
    ),
    "ACP_SECRETS_FILE": (
        "both mock upstreams take an exchanged token (ADR 0028), so there is no "
        "static credential for the store to hold. Wiring an empty secrets store "
        "would demonstrate the loading code and nothing about the control."
    ),
    "ACP_SECRET_KEY_FILE": ("no secrets store, so no key to decrypt it with — see above."),
}


def gateway_environment() -> set[str]:
    """The `ACP_*` names the gateway service's `environment:` block sets.

    Parsed from the file rather than from `docker compose config`, because that
    command RESOLVES interpolation: `${ACP_QUOTA_ENABLED:-true}` renders as
    `true` and a variable that is merely defaulted becomes indistinguishable
    from one that is pinned. Here the question is only whether the file mentions
    the name at all, which the text answers and the rendering hides.
    """
    text = COMPOSE.read_text(encoding="utf-8")
    block = re.search(r"^  gateway:\n(.*?)(?=^  \w)", text, re.MULTILINE | re.DOTALL)
    assert block is not None, "docker-compose.yml has no `gateway:` service"
    return set(re.findall(r"^\s+(ACP_[A-Z0-9_]+):", block.group(1), re.MULTILINE))


def off_by_default() -> dict[str, object]:
    """Every setting whose default leaves a control switched off.

    `False`, `None` and an enum whose value spells "off" — the three shapes an
    unwired feature takes in `GatewaySettings`. Derived, so a feature added
    tomorrow is covered without anybody remembering to add it here.
    """
    found: dict[str, object] = {}
    for name, field in GatewaySettings.model_fields.items():
        default = field.default
        is_off_enum = isinstance(default, enum.Enum) and str(default.value).lower() == "off"
        if default is False or default is None or is_off_enum:
            found[f"ACP_{name.upper()}"] = default
    return found


def test_the_settings_model_still_has_controls_that_default_to_off() -> None:
    """The premise. If this ever comes back empty the check below is vacuous and
    passing for the wrong reason — which is exactly the failure mode of a test
    that guards against absence."""
    assert len(off_by_default()) >= len(DELIBERATELY_OFF)


def test_every_optional_control_is_wired_or_deliberately_not() -> None:
    """The one that would have caught all six.

    A feature that defaults to off and is neither set in compose nor named in
    `DELIBERATELY_OFF` is a feature the demo does not run and nobody decided
    not to run.
    """
    wired = gateway_environment()
    unaccounted = sorted(set(off_by_default()) - wired - set(DELIBERATELY_OFF))
    assert not unaccounted, (
        "these controls default to OFF, are not set in docker-compose.yml, and "
        "are not listed as deliberately off: " + ", ".join(unaccounted) + ". "
        "Either wire them into the gateway's environment or add them to "
        "DELIBERATELY_OFF with the reason."
    )


def test_the_budget_controls_are_wired() -> None:
    """Named individually as well as covered generically, because this is the
    one that shipped: `ACP_COST_FILE` set, and nothing to spend against it.

    A generic assertion that happens to cover a specific regression is not the
    same as an assertion about that regression — the generic one can be
    satisfied by adding a name to `DELIBERATELY_OFF`."""
    wired = gateway_environment()
    assert "ACP_RATE_LIMIT_ENABLED" in wired
    assert "ACP_QUOTA_ENABLED" in wired
    assert "ACP_COST_FILE" in wired, "a cost table with nothing to charge against"


def test_nothing_is_excused_without_a_reason() -> None:
    """`DELIBERATELY_OFF` is an escape hatch, and an escape hatch that takes an
    empty string is how this check gets defeated by the person in a hurry."""
    for name, reason in DELIBERATELY_OFF.items():
        assert len(reason) > 40, f"{name} is excused without a real reason"


def test_the_excuses_are_for_settings_that_exist() -> None:
    """A name that has been renamed in `GatewaySettings` would sit here forever
    excusing nothing, and the real setting would go unchecked."""
    unknown = sorted(set(DELIBERATELY_OFF) - set(off_by_default()))
    assert not unknown, f"excused but not an off-by-default setting: {unknown}"
