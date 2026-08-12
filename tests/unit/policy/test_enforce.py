"""Unit tests for policy enforcement.

``enforce_call`` is the request-path backstop: allow, or raise
``PolicyDeniedError``. The tests pin both halves, the one property that matters
for safety — the raised error carries the deciding rule for the log but says
nothing revealing to the caller — and the property the audit log rests on: that
**both** outcomes are recorded, not only the refusals.
"""

from __future__ import annotations

import logging
from typing import Any

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


# ---------------------------------------------------------------------------
# Every decision is recorded, not only the refusals
# ---------------------------------------------------------------------------

ALLOW_SEARCH = Policy(
    rules=(Rule(name="allow-search", effect=Effect.ALLOW, tools=("mock-a__search",)),)
)


def records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "acp.policy.enforce"]


def fields(record: logging.LogRecord) -> dict[str, Any]:
    """The ``extra`` fields, read off the record as a dictionary.

    ``logging.LogRecord`` has no static knowledge of what ``extra=`` injected,
    so ``record.rule`` is an attribute error to `mypy --strict` even though it
    works at runtime. Reading through ``vars()`` keeps the assertions checking
    the record exactly as a log consumer would — a structured handler serialises
    these fields, it does not read them as attributes — and does it in one place
    rather than in nine ``type: ignore`` comments.
    """
    return vars(record)


def test_an_allowed_call_is_recorded_with_its_rule(caplog: pytest.LogCaptureFixture) -> None:
    """The half that was missing, and the one the audit log depends on.

    A hash chain over refusals alone would faithfully prove the integrity of a
    record containing none of what actually happened. An auditor's first
    question is "what did this agent do", not "what was it refused".
    """
    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(ALLOW_SEARCH, _principal(), "mock-a__search")

    [record] = records(caplog)
    assert record.message == "policy.allowed"
    assert fields(record)["rule"] == "allow-search"
    assert fields(record)["decision"] == "allow"


def test_a_denied_call_is_still_recorded_with_its_rule(caplog: pytest.LogCaptureFixture) -> None:
    denies = Policy(
        rules=(Rule(name="deny-writes", effect=Effect.DENY, tools=("mock-a__create_ticket",)),)
    )

    with (
        caplog.at_level(logging.INFO, logger="acp.policy.enforce"),
        pytest.raises(PolicyDeniedError),
    ):
        enforce_call(denies, _principal(), "mock-a__create_ticket")

    [record] = records(caplog)
    assert record.message == "policy.denied"
    assert fields(record)["rule"] == "deny-writes"
    assert fields(record)["decision"] == "deny"


def test_the_deny_default_is_recorded_with_no_rule(caplog: pytest.LogCaptureFixture) -> None:
    """Nothing matched. The record still exists and says so — a denial with no
    rule is the most important one to be able to explain, because it means the
    policy simply has no opinion about this call."""
    with (
        caplog.at_level(logging.INFO, logger="acp.policy.enforce"),
        pytest.raises(PolicyDeniedError),
    ):
        enforce_call(Policy(rules=()), _principal(), "mock-a__search")

    [record] = records(caplog)
    assert record.message == "policy.denied"
    assert fields(record)["rule"] is None
    assert "no rule matched" in fields(record)["reason"]


def test_both_identities_are_recorded(caplog: pytest.LogCaptureFixture) -> None:
    """The whole authorization model is that the human and the agent are
    different questions. A record naming only the subject can answer "was alice
    allowed to do this" and not "which of the agents acting for alice did it" —
    which is the question that matters when one of them misbehaves."""
    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(ALLOW_SEARCH, _principal(actor="agent-research"), "mock-a__search")

    [record] = records(caplog)
    assert fields(record)["subject"] == "alice"
    assert fields(record)["actor"] == "agent-research"


def test_a_call_with_no_agent_records_a_null_actor(caplog: pytest.LogCaptureFixture) -> None:
    """Absent rather than omitted: a field that disappears on one path is a
    record no query can group by."""
    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(ALLOW_SEARCH, _principal(), "mock-a__search")

    [record] = records(caplog)
    assert fields(record)["actor"] is None


def test_allow_and_deny_records_have_the_same_shape(caplog: pytest.LogCaptureFixture) -> None:
    """One helper writes both, so they cannot drift into carrying different
    fields — which is how an audit record acquires a column on one path only."""
    expected = {"subject", "actor", "tool", "rule", "decision", "reason"}

    with caplog.at_level(logging.INFO, logger="acp.policy.enforce"):
        enforce_call(ALLOW_SEARCH, _principal(), "mock-a__search")
        with pytest.raises(PolicyDeniedError):
            enforce_call(Policy(rules=()), _principal(), "mock-a__search")

    allowed, denied = records(caplog)
    assert expected <= set(fields(allowed))
    assert expected <= set(fields(denied))
