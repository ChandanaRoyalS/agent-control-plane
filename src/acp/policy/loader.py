"""Load and validate a policy document at startup.

Every failure here is a startup failure with a message naming the file, exactly
like ``load_upstreams``. A policy that cannot be read, is not valid YAML, or does
not match the schema stops the gateway from starting — because a gateway that is
a security control and cannot load its rulebook has no safe way to run. The one
thing that is *not* a failure is a policy with no rules: that is a valid document
meaning "deny everything", and the gateway starts and refuses every call.

This is the deny-by-default posture applied to the loader itself. Contrast the
schema-baseline file, which is deliberately non-fatal when missing (a drift
monitor must not be able to stop the gateway). Policy is the opposite: it is the
control, not a monitor of one, so its absence or corruption is fatal.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from acp.exceptions import ConfigurationError
from acp.policy.schema import Policy


def load_policy(path: Path) -> Policy:
    """Read and validate the policy document, or raise ``ConfigurationError``.

    The error messages name the file and, for a schema failure, carry Pydantic's
    own account of which rule and which field were wrong — the thing a human
    reads at 3am, so "validation error for Policy" without a filename is not good
    enough.
    """
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
        # An empty file is not the same as an empty policy. `rules: []` is a
        # deliberate "deny everything"; a zero-byte file is far more likely a
        # truncation or a bad mount, and guessing "deny everything" from it would
        # hide that. Make the deployer write the empty policy explicitly.
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
