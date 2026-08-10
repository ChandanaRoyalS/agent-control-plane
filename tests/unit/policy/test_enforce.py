"""Unit tests for policy enforcement.

``enforce_call`` is the request-path backstop: allow silently, or raise
``PolicyDeniedError``. The tests pin both halves and the one property that matters for
safety — the raised error carries the deciding rule for the log but says nothing
revealing to the caller.
"""

from __future__ import annotations

import pytest

from acp.exceptions import PolicyDeniedError
from acp.identity.principal import Actor, Principal
from acp.policy import Policy, Rule, enforce_call
from acp.policy.schema import Effect

ISSUER = "https://idp.test"


def _principal(subject: str = "alice", actor: str | None = None) -> Principal:
    act = Actor(subject=actor) if actor is not None else None
    return Principal(subject=subject, issuer=ISSUER, actor=act)


def test_allow_returns_none_and_does_not_raise() -> None:
    policy = Policy(
        rules=(Rule(name="allow-search", effect=Effect.ALLOW, tools=("mock-a__search",)),)
    )
    enforce_call(policy, _principal(), "mock-a__search")  # does not raise


def test_explicit_deny_raises_policy_denied(caplog: pytest.LogCaptureFixture) -> None:
    policy = Policy(
        rules=(Rule(name="deny-delete", effect=Effect.DENY, tools=("mock-a__delete",)),)
    )
    with caplog.at_level("INFO"), pytest.raises(PolicyDeniedError):
        enforce_call(policy, _principal(), "mock-a__delete")
    # The rule is logged for the audit trail, not raised to the caller.
    assert any(getattr(r, "rule", None) == "deny-delete" for r in caplog.records)


def test_deny_by_default_raises_with_rule_none() -> None:
    """No rule matched — the deny default. The refusal names no rule, which is
    how the audit log distinguishes 'forbidden by a rule' from 'nothing allowed
    it'."""
    with pytest.raises(PolicyDeniedError):
        enforce_call(Policy(), _principal(), "mock-a__search")


def test_policy_denied_is_not_recoverable() -> None:
    """A denial is permanent for this call: retrying the identical request is
    refused identically, so the agent should stop rather than back off."""
    with pytest.raises(PolicyDeniedError) as exc:
        enforce_call(Policy(), _principal(), "any__tool")
    assert exc.value.recoverable is False


def test_denial_message_does_not_reveal_the_rule() -> None:
    """The caller-facing message must not name the rule or say the tool exists
    but is forbidden — that is an oracle. The rule lives in details, for the log
    only."""
    with pytest.raises(PolicyDeniedError) as exc:
        enforce_call(
            Policy(rules=(Rule(name="secret-deny-rule", effect=Effect.DENY),)),
            _principal(),
            "mock-a__search",
        )
    assert "secret-deny-rule" not in str(exc.value)
    assert "secret-deny-rule" not in str(exc.value.details)
    # details is rendered straight to the JSON-RPC `data` the caller sees, so it
    # must not carry the rule either.
    assert "secret-deny-rule" not in str(exc.value.details)


def test_first_match_wins_through_enforcement() -> None:
    """Enforcement uses the same evaluator, so a narrow deny ahead of a broad
    allow refuses, and an unrelated tool falls through to the allow."""
    policy = Policy(
        rules=(
            Rule(name="deny-delete", effect=Effect.DENY, tools=("mock-a__delete",)),
            Rule(name="allow-all", effect=Effect.ALLOW),
        )
    )
    with pytest.raises(PolicyDeniedError):
        enforce_call(policy, _principal(), "mock-a__delete")
    enforce_call(policy, _principal(), "mock-a__search")  # does not raise


# --- argument-level enforcement (task 37) ---


def test_enforce_denies_when_an_argument_is_not_allowed() -> None:
    """A tool the subject may call, but with a forbidden argument value, is
    refused — the argument check reaches the request path through enforce."""
    policy = Policy(
        rules=(
            Rule(
                name="public-only",
                effect=Effect.ALLOW,
                tools=("mock-a__read_document",),
                args={"doc_id": ("public",)},
            ),
        )
    )
    with pytest.raises(PolicyDeniedError):
        enforce_call(policy, _principal(), "mock-a__read_document", {"doc_id": "secret"})


def test_enforce_allows_when_the_argument_matches() -> None:
    policy = Policy(
        rules=(
            Rule(
                name="public-only",
                effect=Effect.ALLOW,
                tools=("mock-a__read_document",),
                args={"doc_id": ("public",)},
            ),
        )
    )
    enforce_call(policy, _principal(), "mock-a__read_document", {"doc_id": "public"})
