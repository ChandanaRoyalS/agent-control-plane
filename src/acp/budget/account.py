"""The budget account a principal's spend is charged to: tenant plus subject.

Keying on the subject alone would let two tenants' ``alice`` share a bucket, leaking
spend across tenants. The key is a JSON list, so no subject can forge a boundary
with a separator; the limiter and counter key on whatever string they get.
"""

from __future__ import annotations

import json
from typing import Final

PARTIES: Final = 2
"""A tenant and a subject."""


def account(tenant: str | None, subject: str) -> str:
    """Return the account string, e.g. ``["acme","alice"]`` or ``[null,"alice"]``.

    No tenant can share an account with the untenanted pool.
    """
    return json.dumps([tenant, subject], separators=(",", ":"), ensure_ascii=False)


def parties(payer: str) -> tuple[str | None, str | None]:
    """Return the (tenant, subject) an account names, for display (the trace console).

    Never raises: anything this module did not write gives ``(None, None)``.
    """
    try:
        decoded = json.loads(payer)
    except (json.JSONDecodeError, TypeError):
        return (None, None)
    if not isinstance(decoded, list) or len(decoded) != PARTIES:
        return (None, None)
    tenant, subject = decoded
    return (
        tenant if isinstance(tenant, str) else None,
        subject if isinstance(subject, str) else None,
    )
