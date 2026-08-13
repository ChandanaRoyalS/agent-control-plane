"""Fail-closed, redaction order, and the record's shape.

Task 56. `AuditLog` is the seam the request path calls and the single place the
decision about an unwritable record is made.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from acp.audit.chain import verify
from acp.audit.record import Category, Outcome
from acp.audit.sink import MemoryAuditSink
from acp.audit.writer import FAILURE_EVENT, AuditLog
from acp.exceptions import AuditUnavailableError


class BrokenSink:
    """A sink that cannot write, which is the only interesting failure here."""

    head = "0" * 64
    length = 0

    def append(self, _record: Any) -> Any:
        raise OSError("no space left on device")

    def close(self) -> None:
        """Part of the protocol, so the double stays a double.

        `close` was added to `AuditSink` after a leaked handle, and mypy
        immediately reported this class as no longer satisfying it — which is
        the argument for putting `close` on the protocol rather than treating it
        as a detail of the file sink. A double that quietly diverges from the
        interface is one that stops testing the thing it stands for.
        """


def written(sink: MemoryAuditSink) -> list[dict[str, Any]]:
    return [json.loads(line)["record"] for line in sink.lines()]


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def test_an_unwritable_record_refuses_the_call() -> None:
    """**The guarantee.** An audit log that stops recording while the gateway
    keeps serving is worse than none, because the record then asserts by
    omission that nothing happened during the window somebody will ask about."""
    audit = AuditLog(BrokenSink(), required=True)

    with pytest.raises(AuditUnavailableError):
        audit.record(Category.AUTHORIZATION, "policy.decision", subject="alice")


def test_the_refusal_names_nothing_on_the_wire() -> None:
    """A caller told "the audit log is down" has learned which subsystem to
    attack in order to stop being recorded — a strictly more valuable thing to
    know than the fact they were refused."""
    audit = AuditLog(BrokenSink(), required=True)

    with pytest.raises(AuditUnavailableError) as caught:
        audit.record(Category.AUTHORIZATION, "policy.decision")

    assert "audit" not in str(caught.value).lower()
    assert "space" not in str(caught.value).lower()


def test_opting_out_lets_the_call_proceed(caplog: pytest.LogCaptureFixture) -> None:
    """`ACP_AUDIT_REQUIRED=false` is a real mode and a loud one."""
    audit = AuditLog(BrokenSink(), required=False)

    with caplog.at_level(logging.ERROR, logger="acp.audit.writer"):
        assert audit.record(Category.AUTHORIZATION, "policy.decision") is None

    [failure] = [r for r in caplog.records if r.message == FAILURE_EVENT]
    assert "no record of it" in getattr(failure, "consequence", "")


def test_the_failure_is_reported_somewhere_other_than_the_audit_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The record of the record's failure needs a different sink, or it is not a
    record at all. It goes to the operational log at ERROR, and to a metric."""
    audit = AuditLog(BrokenSink(), required=True)

    with (
        caplog.at_level(logging.ERROR, logger="acp.audit.writer"),
        pytest.raises(AuditUnavailableError),
    ):
        audit.record(Category.AUTHORIZATION, "policy.decision")

    assert [r for r in caplog.records if r.message == FAILURE_EVENT]


# ---------------------------------------------------------------------------
# Redaction, and its order
# ---------------------------------------------------------------------------


def test_a_credential_in_a_detail_is_redacted() -> None:
    sink = MemoryAuditSink()
    AuditLog(sink).record(
        Category.CREDENTIAL,
        "auth.exchanged",
        detail={"authorization": "Bearer super-secret", "audience": "acp-upstream-mock-a"},
    )

    [record] = written(sink)

    assert record["detail"]["authorization"] == "[redacted]"
    assert record["detail"]["audience"] == "acp-upstream-mock-a"


def test_redaction_happens_before_the_hash() -> None:
    """**The ordering that makes the file verifiable.**

    If the digest were taken over the unredacted record, a verifier reading the
    file would recompute a different hash and report tampering on a log nobody
    touched — the worst possible false positive from a tool whose only job is
    detecting real ones.
    """
    sink = MemoryAuditSink()
    AuditLog(sink).record(Category.CREDENTIAL, "auth.exchanged", detail={"token": "super-secret"})

    assert verify(sink.lines()).intact
    assert "super-secret" not in sink.lines()[0]


# ---------------------------------------------------------------------------
# The record's shape
# ---------------------------------------------------------------------------


def test_every_record_has_the_same_keys() -> None:
    """A record whose shape depends on the outcome is one no query can group by."""
    sink = MemoryAuditSink()
    audit = AuditLog(sink)
    audit.record(Category.AUTHORIZATION, "policy.decision", subject="alice")
    audit.record(
        Category.TOOL_CALL,
        "tool.called",
        subject="bob",
        tool="mock-a__search",
        outcome=Outcome.COMPLETED,
        detail={"anything": 1},
    )

    first, second = written(sink)

    assert first.keys() == second.keys()


def test_absent_fields_are_present_and_null() -> None:
    """Dropped and unknown are the same bytes to a verifier and different facts
    to an auditor."""
    sink = MemoryAuditSink()
    AuditLog(sink).record(Category.AUTHORIZATION, "policy.decision")

    [record] = written(sink)

    assert record["tenant"] is None
    assert "tenant" in record


def test_the_tenant_is_carried() -> None:
    """Present from the first version, so an archived chain never has to be
    migrated — rewriting one is exactly what the chain exists to detect."""
    sink = MemoryAuditSink()
    AuditLog(sink).record(Category.AUTHORIZATION, "policy.decision", tenant="acme")

    assert written(sink)[0]["tenant"] == "acme"


def test_the_clock_is_injected() -> None:
    """Tests advance a number rather than sleeping, the same injection the rate
    limiter and the approval flow use."""
    sink = MemoryAuditSink()
    AuditLog(sink, clock=lambda: 1786600000.0).record(Category.AUTHORIZATION, "policy.decision")

    assert written(sink)[0]["at"] == 1786600000.0
