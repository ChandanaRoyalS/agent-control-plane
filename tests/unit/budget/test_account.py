"""The budget account: one string, and the boundary it carries.

Task 58. The limiter and quota counter key on whatever string they are given,
so isolation lives entirely in this function — which is why its tests are
about collisions, not about arithmetic.
"""

from __future__ import annotations

from acp.budget import RateLimiter, account, enforce_rate_limit, parties


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


# ---------------------------------------------------------------------------
# Reading it back — task 63
# ---------------------------------------------------------------------------


def test_an_account_round_trips() -> None:
    assert parties(account("acme", "alice")) == ("acme", "alice")


def test_an_untenanted_account_round_trips_with_no_tenant() -> None:
    """`None` and a real label are different accounts by construction, and the
    inverse has to preserve that or the console shows an untenanted principal
    as belonging to a tenant called `null`."""
    assert parties(account(None, "alice")) == (None, "alice")


def test_a_subject_containing_the_separator_survives() -> None:
    """THE CASE THE LIST ENCODING EXISTS FOR. Splitting on a comma at the call
    site would have read this subject as a tenant — and the display would
    attribute one principal's spend to another's tenant."""
    payer = account("acme", 'al,ice"]')
    assert parties(payer) == ("acme", 'al,ice"]')


def test_a_subject_with_a_comma_is_not_confusable_with_a_tenant() -> None:
    """The stronger form: two different principals must not decode alike."""
    assert parties(account(None, "acme,alice")) != parties(account("acme", "alice"))


def test_something_that_is_not_an_account_decodes_to_nothing() -> None:
    """A display path is not the place to raise. The value came from a
    dictionary key inside a running gateway, and a console that crashes on an
    unfamiliar one is worse than a console that renders it blank."""
    assert parties("not json") == (None, None)
    assert parties("[1,2,3]") == (None, None)
    assert parties('{"tenant":"acme"}') == (None, None)
    assert parties("[1,2]") == (None, None)
