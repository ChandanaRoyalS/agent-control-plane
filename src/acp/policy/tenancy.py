"""One policy per tenant, selected by an identity nothing downstream can forge.

Task 58. The plan asks for "isolated policy, budgets and credentials per
tenant", and this module is the policy third. The other two need no module:
budgets and the result cache isolate by *widening their keys* with the tenant
(`acp.budget.account`, `acp.results.cache.key_for`), and credentials were
tenant-safe before the task existed — the exchange goes to each registration's
own token endpoint and its cache keys on a digest of the subject token itself,
which no two tenants can share.

**Why a file per tenant rather than tenant sections in one file.** Isolation by
file boundary holds *by construction*: no rule in tenant A's file can match
tenant B's traffic, because tenant B's evaluation never opens tenant A's file.
Isolation by section holds by matcher discipline — a code property that must be
tested and re-tested every time the evaluator changes. This project prefers the
property that cannot regress (the same argument as the operator channel living
on a listener the agent cannot address, made against a different substrate).

**Selection is total and fail-closed.** Three cases, none of which fall through
to another tenant's rules:

- ``tenant=None`` — a principal from a registration with no tenant label. Gets
  the default policy: the single-tenant gateway, behaving exactly as it did
  before task 58 existed.
- a known tenant — gets its own policy and nothing else.
- an unknown tenant — gets ``DENY_ALL``. This "cannot happen" (tenants come
  from issuer registrations, and every registered tenant is required to have a
  policy at startup), which is precisely why the case is handled: the claim
  rests on startup code in another module, and a refactor there should degrade
  this module to refusing everything, not to handing one tenant another
  tenant's rules. **The default policy would be the natural fallback and is the
  one wrong answer** — it is some *other* tenant's rule set.
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
"""What an unknown tenant is evaluated against. ``rules: ()`` is the deny
default with nothing in front of it — ADR 0025's floor, used as a floor."""


@dataclass(frozen=True, slots=True)
class PolicySet:
    """Every policy this gateway holds, and the one rule for choosing between them.

    Frozen, like the policies it holds: the set is built once at startup and
    selection is the only operation. A mutable registry that tenants could be
    added to at runtime would make "which policy decided this call" a question
    about *when*, and the audit chain records rule names on the assumption that
    a name means one thing.
    """

    default: Policy
    tenants: Mapping[str, Policy] = field(default_factory=dict)

    def policy_for(self, tenant: str | None) -> Policy:
        """The one policy this principal is evaluated against.

        Total — every input returns a policy, and the failure direction is
        chosen per case. ``None`` is the single-tenant gateway and gets the
        default. A named tenant gets its own file. A tenant this set has never
        heard of gets ``DENY_ALL`` — never the default, because the default is
        somebody else's policy, and "an unconfigured tenant inherits whatever
        the untenanted rules happen to allow" is a cross-tenant grant written
        as a fallback.
        """
        if tenant is None:
            return self.default
        return self.tenants.get(tenant, DENY_ALL)

    @property
    def gates_calls(self) -> bool:
        """Whether ANY policy here can hold a call for a person.

        The approval store must exist if any tenant's rules can hold a call —
        a store sized to the default policy alone would refuse to hold exactly
        the calls a tenant's rule was written to hold.
        """
        return self.default.gates_calls or any(p.gates_calls for p in self.tenants.values())


def load_policy_set(
    default_path: Path,
    *,
    tenant_policy_dir: Path | None,
    tenants: frozenset[str],
) -> PolicySet:
    """Build the whole set at startup, or refuse to start.

    ``tenants`` is the set of labels the issuer registrations declare — the
    only place tenants come from. Every declared tenant must have
    ``<dir>/<tenant>.yaml``, and a missing file is a **startup failure naming
    the tenant**, not a silent deny-all. Deny-all is the right answer for a
    tenant that appears at runtime against this set's knowledge; it is the
    wrong answer for a configuration typo, because a tenant whose every call
    answers "forbidden" with no explanation is an outage dressed as a policy,
    and the person debugging it is three layers away from the missing file.

    Declaring tenants with no ``tenant_policy_dir`` set is the same failure
    for the same reason: the labels promise isolation the configuration does
    not deliver, and the promise should fail where it was made.

    The label was validated at registration (`TENANT_LABEL` in
    `acp.identity.issuers`) to a slug that cannot traverse a path, which is
    what makes ``dir / f"{tenant}.yaml"`` safe to assemble here.
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
