"""Load a cost table from a YAML document, or raise ConfigurationError.

The file is a mapping: a ``costs`` map of qualified tool name to cost, and an
optional ``default`` for tools not named. Absent file means no weighting — the
caller supplies the default table (every call costs one), so a deployment
without a costs file behaves exactly as task 38 left it.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from acp.budget.cost import CostTable
from acp.exceptions import ConfigurationError


def _validate_cost(name: str, value: object, path: Path) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"costs file {str(path)!r}: cost for {name!r} must be a number, got {value!r}"
        raise ConfigurationError(msg)
    cost = float(value)
    if cost < 0:
        msg = f"costs file {str(path)!r}: cost for {name!r} must not be negative"
        raise ConfigurationError(msg)
    return cost


def load_costs(path: Path) -> CostTable:
    """Read and validate the costs document, or raise ``ConfigurationError``.

    Errors name the file and the offending entry — the account a human reads
    when a deploy fails, so a bare "invalid" is not enough.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read costs file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"costs file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc

    if document is None:
        # An empty file is ambiguous: no costs, or a truncated mount? Rather than
        # guess, make the deployer say `costs: {}` to mean "no weighting".
        msg = (
            f"costs file {str(path)!r} is empty. Write `costs: {{}}` to mean "
            f"'no per-tool weighting', or add costs."
        )
        raise ConfigurationError(msg)

    if not isinstance(document, dict):
        msg = f"costs file {str(path)!r} must be a mapping with a `costs` key"
        raise ConfigurationError(msg)

    raw_costs = document.get("costs", {})
    if not isinstance(raw_costs, dict):
        msg = f"costs file {str(path)!r}: `costs` must be a mapping of tool to cost"
        raise ConfigurationError(msg)

    costs = {name: _validate_cost(name, value, path) for name, value in raw_costs.items()}

    default: float = 1.0
    if "default" in document:
        default = _validate_cost("default", document["default"], path)

    return CostTable(costs=costs, default=default)
