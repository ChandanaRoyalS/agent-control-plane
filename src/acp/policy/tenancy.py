"""One policy per tenant, selected by an identity nothing downstream can forge.

Budgets and the result cache isolate tenants by key (`acp.budget.account`,
`acp.results.cache.key_for`); credentials already key on the subject token. Policy
uses a file per tenant, so isolation holds by construction rather than by matcher
discipline. Selection is fail-closed: an untenanted principal gets the default
policy, a known tenant its own, and an unknown tenant ``DENY_ALL``, never the default.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from acp.exceptions import ConfigurationError
from acp.policy.loader import load_policy
from acp.policy.schema import Policy

DENY_ALL: Final = Policy(rules=())
"""What an unknown tenant is evaluated against: the bare deny default (ADR 0025)."""


@dataclass(frozen=True, slots=True)
class PolicySet:
    """Every policy this gateway holds; built once at startup and frozen."""

    default: Policy
    tenants: Mapping[str, Policy] = field(default_factory=dict)

    def policy_for(self, tenant: str | None) -> Policy:
        """Return the tenant's policy: the default for ``None``, ``DENY_ALL`` if unknown."""
        if tenant is None:
            return self.default
        return self.tenants.get(tenant, DENY_ALL)

    @property
    def gates_calls(self) -> bool:
        """Whether any policy here, tenant or default, can hold a call for a person."""
        return self.default.gates_calls or any(p.gates_calls for p in self.tenants.values())


def load_policy_set(
    default_path: Path,
    *,
    tenant_policy_dir: Path | None,
    tenants: frozenset[str],
) -> PolicySet:
    """Build the whole set at startup, or refuse to start.

    ``tenants`` are the labels the issuer registrations declare. Each needs
    ``<dir>/<tenant>.yaml``.

    Raises:
        ConfigurationError: if a tenant's file is missing, or tenants are declared
            without ``tenant_policy_dir``; a silent deny-all would be an outage.

    Labels are path-safe slugs (`TENANT_LABEL` in `acp.identity.issuers`).
    """
    if tenants and tenant_policy_dir is None:
        listed = ", ".join(sorted(tenants))
        msg = (
            f"issuers declare tenants ({listed}) but ACP_TENANT_POLICY_DIR is "
            f"not set. A tenant label with no policy behind it promises "
            f"isolation the configuration does not deliver — set the directory "
            f"and write one policy file per tenant, or remove the labels."
        )
        raise ConfigurationError(msg)

    loaded: dict[str, Policy] = {}
    for tenant in sorted(tenants):
        if tenant_policy_dir is None:  # pragma: no cover — refused above when tenants exist
            break
        path = tenant_policy_dir / f"{tenant}.yaml"
        if not path.exists():
            msg = (
                f"tenant {tenant!r} is declared in the issuers file but has no "
                f"policy at {str(path)!r}. Write one (`rules: []` to mean 'deny "
                f"everything' explicitly), or remove the tenant label. Refusing "
                f"to guess, because a tenant silently denied everything is an "
                f"outage dressed as a policy."
            )
            raise ConfigurationError(msg)
        loaded[tenant] = load_policy(path)

    return PolicySet(default=load_policy(default_path), tenants=loaded)
