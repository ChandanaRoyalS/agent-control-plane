"""One policy per tenant, and the selection rule that keeps them apart.

Task 58. The load-bearing assertions are the negative ones: an unknown tenant
gets DENY_ALL and **not** the default, and a missing policy file refuses to
start rather than silently denying. Both are cases where a plausible fallback
exists and is the wrong answer — the default policy is some other tenant's
rules, and a silent deny-all is an outage dressed as a policy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acp.exceptions import ConfigurationError
from acp.identity.principal import Principal
from acp.policy.evaluate import evaluate
from acp.policy.schema import Effect, Policy, Rule
from acp.policy.tenancy import DENY_ALL, PolicySet, load_policy_set

ALLOW_SEARCH = Policy(rules=(Rule(name="allow-search", effect=Effect.ALLOW),))
ACME_ONLY = Policy(rules=(Rule(name="acme-search", effect=Effect.ALLOW, subjects=("alice",)),))
GATED = Policy(rules=(Rule(name="hold-it", effect=Effect.REQUIRE_APPROVAL),))


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_no_tenant_gets_the_default_policy() -> None:
    """The single-tenant gateway: task 58 changes nothing for it."""
    policies = PolicySet(default=ALLOW_SEARCH, tenants={"acme": ACME_ONLY})
    assert policies.policy_for(None) is ALLOW_SEARCH


def test_a_known_tenant_gets_its_own_policy_and_nothing_else() -> None:
    policies = PolicySet(default=ALLOW_SEARCH, tenants={"acme": ACME_ONLY})
    assert policies.policy_for("acme") is ACME_ONLY


def test_an_unknown_tenant_gets_deny_all_not_the_default() -> None:
    """The assertion this module exists for.

    The default policy is the natural fallback and the one wrong answer: it is
    some *other* tenant's rule set, and "an unconfigured tenant inherits
    whatever the untenanted rules allow" is a cross-tenant grant written as a
    fallback. DENY_ALL has no rules, so the deny default decides everything.
    """
    policies = PolicySet(default=ALLOW_SEARCH, tenants={"acme": ACME_ONLY})
    chosen = policies.policy_for("globex")
    assert chosen is DENY_ALL
    assert chosen is not ALLOW_SEARCH
    assert chosen.rules == ()


def test_a_bare_policy_wrapped_as_a_set_is_the_default() -> None:
    """`PolicySet(policy)` is the normalisation the gateway performs, and a
    tenanted principal arriving at it must fall to DENY_ALL — the set knows no
    tenants, so every tenant is unknown."""
    policies = PolicySet(ALLOW_SEARCH)
    assert policies.policy_for(None) is ALLOW_SEARCH
    assert policies.policy_for("acme") is DENY_ALL


# ---------------------------------------------------------------------------
# gates_calls: the approval store must exist if ANY policy can hold a call
# ---------------------------------------------------------------------------


def test_gates_calls_sees_a_gating_tenant_behind_an_ungated_default() -> None:
    policies = PolicySet(default=ALLOW_SEARCH, tenants={"acme": GATED})
    assert policies.gates_calls


def test_gates_calls_is_false_when_nothing_gates() -> None:
    policies = PolicySet(default=ALLOW_SEARCH, tenants={"acme": ACME_ONLY})
    assert not policies.gates_calls


def test_gates_calls_sees_a_gating_default() -> None:
    assert PolicySet(default=GATED).gates_calls


# ---------------------------------------------------------------------------
# Loading: every declared tenant has a file, or the process does not start
# ---------------------------------------------------------------------------


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


DEFAULT_YAML = """
rules:
  - name: allow-everything
    effect: allow
"""

TENANT_YAML = """
rules:
  - name: acme-search
    effect: allow
    subjects: ["alice"]
"""


def test_load_builds_the_whole_set(tmp_path: Path) -> None:
    default = _write(tmp_path / "policy.yaml", DEFAULT_YAML)
    tenant_dir = tmp_path / "tenants"
    tenant_dir.mkdir()
    _write(tenant_dir / "acme.yaml", TENANT_YAML)

    policies = load_policy_set(default, tenant_policy_dir=tenant_dir, tenants=frozenset({"acme"}))
    assert policies.policy_for("acme").rules[0].name == "acme-search"
    assert policies.policy_for(None).rules[0].name == "allow-everything"


def test_a_declared_tenant_with_no_file_refuses_to_start(tmp_path: Path) -> None:
    """Never a silent deny-all. A configuration typo must fail where it was
    made, naming the tenant and the path, because the person debugging "every
    call from acme is forbidden" is three layers away from the missing file."""
    default = _write(tmp_path / "policy.yaml", DEFAULT_YAML)
    tenant_dir = tmp_path / "tenants"
    tenant_dir.mkdir()

    with pytest.raises(ConfigurationError, match="acme") as excinfo:
        load_policy_set(default, tenant_policy_dir=tenant_dir, tenants=frozenset({"acme"}))
    assert "acme.yaml" in str(excinfo.value)


def test_declared_tenants_with_no_directory_refuse_to_start(tmp_path: Path) -> None:
    """A tenant label with no policy dir promises isolation the configuration
    does not deliver, and the promise fails where it was made."""
    default = _write(tmp_path / "policy.yaml", DEFAULT_YAML)

    with pytest.raises(ConfigurationError, match="ACP_TENANT_POLICY_DIR"):
        load_policy_set(default, tenant_policy_dir=None, tenants=frozenset({"acme"}))


def test_no_tenants_and_no_directory_is_the_single_tenant_gateway(tmp_path: Path) -> None:
    default = _write(tmp_path / "policy.yaml", DEFAULT_YAML)
    policies = load_policy_set(default, tenant_policy_dir=None, tenants=frozenset())
    assert policies.tenants == {}
    assert policies.policy_for(None).rules[0].name == "allow-everything"


def test_a_broken_tenant_policy_is_a_startup_failure(tmp_path: Path) -> None:
    """`load_policy`'s discipline applies per tenant file: an empty file, bad
    YAML or a schema violation names the file and refuses to boot."""
    default = _write(tmp_path / "policy.yaml", DEFAULT_YAML)
    tenant_dir = tmp_path / "tenants"
    tenant_dir.mkdir()
    _write(tenant_dir / "acme.yaml", "")  # empty: load_policy refuses these

    with pytest.raises(ConfigurationError, match=r"acme\.yaml"):
        load_policy_set(default, tenant_policy_dir=tenant_dir, tenants=frozenset({"acme"}))


# ---------------------------------------------------------------------------
# The isolation property, end to end through the evaluator
# ---------------------------------------------------------------------------


def test_one_tenants_allow_cannot_reach_another_tenants_traffic() -> None:
    """The plan's own sentence — "tests proving one tenant cannot reach
    another's" — for policy. acme's broad allow decides nothing for globex:
    globex's alice is evaluated against globex's (absent) rules and denied,
    even though acme's file would have allowed the identical request.
    """
    policies = PolicySet(default=DENY_ALL, tenants={"acme": ALLOW_SEARCH})

    acme_alice = Principal(subject="alice", issuer="https://idp.acme.test", tenant="acme")
    globex_alice = Principal(subject="alice", issuer="https://idp.globex.test", tenant="globex")

    allowed = evaluate(policies.policy_for(acme_alice.tenant), acme_alice, "mock-a__search", {})
    denied = evaluate(policies.policy_for(globex_alice.tenant), globex_alice, "mock-a__search", {})
    assert allowed.allowed
    assert not denied.allowed
