"""Load and validate a policy document at startup.

An unreadable, invalid or empty file fails startup with a message naming it: the
gateway has no safe way to run without its rulebook. `rules: []` is valid and denies
everything.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from acp.exceptions import ConfigurationError
from acp.policy.schema import Policy


def load_policy(path: Path) -> Policy:
    """Read and validate the policy document, or raise ``ConfigurationError`` naming the file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read policy file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"policy file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc

    if document is None:
        # An empty file is likely truncation or a bad mount, not an empty policy.
        msg = (
            f"policy file {str(path)!r} is empty. Write `rules: []` to mean "
            f"'deny everything' explicitly, or add rules."
        )
        raise ConfigurationError(msg)

    if not isinstance(document, dict):
        msg = f"policy file {str(path)!r} must be a mapping with a `rules` key"
        raise ConfigurationError(msg)

    try:
        return Policy.model_validate(document)
    except ValidationError as exc:
        msg = f"policy file {str(path)!r} is invalid: {exc}"
        raise ConfigurationError(msg) from exc
