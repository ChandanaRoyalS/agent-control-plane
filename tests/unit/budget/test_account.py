"""The budget account: one string, and the boundary it carries.

Task 58. The limiter and quota counter key on whatever string they are given,
so isolation lives entirely in this function — which is why its tests are
about collisions, not about arithmetic.
"""

from __future__ import annotations

from acp.budget import RateLimiter, account, enforce_rate_limit


def test_two_tenants_same_subject_are_two_accounts() -> None:
    assert account("acme", "alice") != account("globex", "alice")


def test_untenanted_and_tenanted_never_share_an_account() -> None:
    """`None` is not a label a tenant can have (the slug regex has no spelling
    for it), so the untenanted pool is unreachable from every tenant."""
    assert account(None, "alice") != account("acme", "alice")


def test_a_subject_cannot_forge_a_tenant_boundary() -> None:
    """The classic canonicalisation attack, refused by the JSON-list encoding.

    With a separator join, tenant `acme` + subject `x","y` could collide with
    a differently split pair. The list encoding quotes the comma, so the two
    accounts differ.
    """
    assert account("acme", 'alice","extra') != account('acme","alice', "extra")
    assert account(None, '["acme","alice"]') != account("acme", "alice")


def test_the_account_is_stable() -> None:
    """Buckets persist across calls under the same key, so the encoding must be
    deterministic — no dict ordering, no whitespace drift."""
    assert account("acme", "alice") == account("acme", "alice")
    assert account("acme", "alice") == '["acme","alice"]'


def test_one_tenants_spend_cannot_drain_anothers_bucket() -> None:
    """The plan's isolation sentence, for budgets: acme's alice exhausts her
    bucket, and globex's alice still has a full one."""
    limiter = RateLimiter(capacity=2.0, refill_per_second=0.0001)

    now = 0.0
    enforce_rate_limit(limiter, account("acme", "alice"), now)
    enforce_rate_limit(limiter, account("acme", "alice"), now)

    # acme's alice is now empty; globex's alice is untouched.
    enforce_rate_limit(limiter, account("globex", "alice"), now)
    enforce_rate_limit(limiter, account("globex", "alice"), now)
