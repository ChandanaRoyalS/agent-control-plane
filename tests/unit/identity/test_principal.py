"""Unit tests for reading a principal out of verified claims.

Pure claim-reading, deliberately separate from anything cryptographic. The
mistakes worth catching here are about *interpretation* — which identity is the
user and which is the agent — and they are far easier to see when signature
verification is not in the same test.
"""

from __future__ import annotations

from typing import Any

import pytest

from acp.identity.principal import (
    MAX_DELEGATION_DEPTH,
    Actor,
    Principal,
    bind_principal,
    current_principal,
    from_claims,
)


def base(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"sub": "alice", "iss": "https://idp.test"}
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Two identities, not one
# ---------------------------------------------------------------------------


def test_the_subject_and_the_actor_are_kept_apart() -> None:
    """The whole point of the phase. `sub` is the human the work is for; `act`
    is the workload doing it. Policy about what may be read is about the first;
    policy about which agent may act at all is about the second."""
    principal = from_claims(base(act={"sub": "agent-7", "iss": "https://workloads.test"}))

    assert principal.subject == "alice"
    assert principal.actor == Actor(subject="agent-7", issuer="https://workloads.test")
    assert principal.is_delegated is True


def test_a_token_with_no_actor_is_not_delegated() -> None:
    """A human calling the gateway directly. Legitimate, and a different
    situation from an agent acting for them — so it must not be dressed up as
    one."""
    principal = from_claims(base())

    assert principal.actor is None
    assert principal.is_delegated is False
    assert principal.label == "alice"


def test_the_label_shows_both_halves() -> None:
    """A log line that renders "alice" and "alice acting through an agent"
    identically cannot answer the only question worth asking after an
    incident."""
    assert from_claims(base(act={"sub": "agent-7"})).label == "alice via agent-7"


def test_a_delegation_chain_is_recorded_outermost_first() -> None:
    """RFC 8693 nests `act`, so `act.act` is who delegated to `act`. The
    immediate actor decides authorization now; the rest is provenance worth
    keeping, because "the CFO's token, via an agent, via a scheduler nobody
    authorized" should be answerable from an audit log."""
    principal = from_claims(
        base(act={"sub": "agent-7", "act": {"sub": "scheduler", "act": {"sub": "cron"}}})
    )

    assert principal.actor == Actor(subject="agent-7")
    assert principal.delegation_chain == ("agent-7", "scheduler", "cron")


def test_a_chain_deeper_than_the_limit_does_not_run_away() -> None:
    """The claim nests arbitrarily and arrives from outside. An unbounded walk
    over it is a denial of service written in JSON — a small string that costs
    the gateway a lot of work."""
    deepest: dict[str, Any] = {"sub": "level-0"}
    for level in range(1, 200):
        deepest = {"sub": f"level-{level}", "act": deepest}

    principal = from_claims(base(act=deepest))

    assert len(principal.delegation_chain) == MAX_DELEGATION_DEPTH


def test_a_malformed_actor_ends_the_chain_rather_than_failing_the_token() -> None:
    """An `act` with no `sub` names nobody. Rejecting a whole token over a
    cosmetic bug in an optional provenance record would turn an identity
    provider's mistake into an outage here."""
    principal = from_claims(base(act={"iss": "https://workloads.test"}))

    assert principal.actor is None
    assert principal.delegation_chain == ()


# ---------------------------------------------------------------------------
# Claims that must be present, and claims that need not be
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["sub", "iss"])
def test_a_token_that_names_nobody_is_unusable(missing: str) -> None:
    """Signed, unexpired, correctly addressed — and it does not say who it is
    for. Accepting it would mean a request executing under no principal while
    every log line claimed otherwise."""
    payload = base()
    del payload[missing]

    with pytest.raises(ValueError, match=missing):
        from_claims(payload)


@pytest.mark.parametrize("value", ["", None, 42, {"nested": "object"}])
def test_a_subject_that_is_not_a_non_empty_string_is_rejected(value: Any) -> None:
    with pytest.raises(ValueError, match="sub"):
        from_claims(base(sub=value))


def test_scope_is_space_delimited_per_rfc_6749() -> None:
    assert from_claims(base(scope="tools:read tools:call")).scopes == {"tools:read", "tools:call"}


def test_a_provider_that_sends_scope_as_a_list_is_tolerated() -> None:
    """Wrong by the letter of RFC 6749 §3.3 and common in practice. Rejecting it
    would be correct and would break against real identity providers for no
    security benefit whatsoever."""
    assert from_claims(base(scope=["a", "b"])).scopes == {"a", "b"}


def test_absent_optional_claims_do_not_invent_values() -> None:
    principal = from_claims(base())

    assert principal.scopes == frozenset()
    assert principal.client_id is None
    assert principal.expires_at is None


def test_a_boolean_is_not_an_expiry() -> None:
    """`isinstance(True, int)` is True in Python, so a naive check accepts
    `exp: true` and produces an expiry of 1 — the epoch plus one second."""
    assert from_claims(base(exp=True)).expires_at is None


# ---------------------------------------------------------------------------
# What reaches the logs
# ---------------------------------------------------------------------------


def test_log_fields_carry_identifiers_and_nothing_else() -> None:
    """An audit trail needs to say *which principal*, not *who the person is*.
    The two have very different retention rules attached, and a gateway that
    copies an email onto every log line has made that decision for whoever
    operates it."""
    principal = from_claims(
        base(act={"sub": "agent-7"}, email="alice@example.test", name="Alice Example")
    )

    fields = principal.as_log_fields()

    assert fields == {
        "principal": "alice",
        "principal_issuer": "https://idp.test",
        "actor": "agent-7",
        "client_id": None,
        "tenant": None,
    }
    assert "alice@example.test" not in str(fields)
    assert "Alice Example" not in str(fields)


def test_scopes_are_queryable() -> None:
    principal = from_claims(base(scope="tools:read"))

    assert principal.has_scope("tools:read")
    assert not principal.has_scope("tools:write")


# ---------------------------------------------------------------------------
# The current request's principal
# ---------------------------------------------------------------------------


def test_unauthenticated_is_none_rather_than_a_stand_in_object() -> None:
    """The design decision this file rests on. An "anonymous principal" looks
    like a principal to every caller that forgets to check, and forgetting to
    check is the entire failure mode. `None` makes `mypy --strict` refuse to
    compile the code that forgets."""
    bind_principal(None)

    assert current_principal() is None


def test_a_bound_principal_is_readable_without_being_passed_anywhere() -> None:
    principal = Principal(subject="alice", issuer="https://idp.test")
    bind_principal(principal)
    try:
        assert current_principal() is principal
    finally:
        bind_principal(None)
