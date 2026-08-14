"""What a budget is charged to, once tenancy exists.

Task 58. The rate limiter and the quota counter key their dictionaries on a
string, and until now that string was ``principal.subject`` — which is unique
within one identity provider and nothing more. Two tenants whose IdPs each
have an ``alice`` would share a bucket: one tenant's spend exhausts the
other's allowance, which is cross-tenant interference in the polite direction
and cross-tenant *reconnaissance* in the other (drain your own bucket, observe
whether a stranger's calls slow down).

One function, used by every charge site, so the question "what is a budget
account" has exactly one answer. The encoding is a JSON list for the same
reason the result-cache key is: joining with a separator invites a subject
containing that separator to forge a boundary, and a list encoding makes that
impossible rather than unlikely.

The limiter and counter themselves are untouched — they key on whatever string
they are given. Isolation lives in the key, exactly as it does in the result
cache, and for the same reason: a account too narrow costs fairness, an
account too broad is shared state between strangers.
"""

from __future__ import annotations

import json
from typing import Final

PARTIES: Final = 2
"""A tenant and a subject. Named so the length check below is a statement
rather than a magic number."""


def account(tenant: str | None, subject: str) -> str:
    """The string a principal's spend is charged against.

    ``None`` and a real label produce different accounts by construction —
    ``[null,"alice"]`` and ``["acme","alice"]`` — so an untenanted deployment
    keeps its existing per-subject behaviour byte-for-byte, and no tenant can
    ever share an account with the untenanted pool.
    """
    return json.dumps([tenant, subject], separators=(",", ":"), ensure_ascii=False)


def parties(payer: str) -> tuple[str | None, str | None]:
    """The inverse: which tenant and subject an account string names.

    Here rather than at the call site because **the format has an owner**, and
    the one place that writes it is the only place that should claim to read it.
    The trace console (task 63) wants to display who spent, and doing that by
    splitting on a comma would be string surgery on somebody else's encoding —
    which works until a subject contains a comma, which is precisely the case
    the list encoding above exists to make harmless.

    Returns `(None, None)` for anything that is not an account this module
    wrote. A display path is not the place to raise: the value came from a
    dictionary key inside a running gateway, and a console that crashes on an
    unfamiliar one is worse than a console that renders it blank.
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
