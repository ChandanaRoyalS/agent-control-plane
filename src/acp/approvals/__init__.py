"""Human-in-the-loop approvals: a call that stops and waits for a person.

When policy says `require_approval` (ADR 0048), the gateway answers
`input_required` with an opaque `request_state` and the client retries with it
once a human decides; nothing is held open (ADR 0001). An approval is bound to the
exact call: the retry is re-fingerprinted and compared (`record.py`).
"""

from acp.approvals.flow import Gate, Outcome, Resolution, gate, resolve
from acp.approvals.operator import (
    APPROVAL_PATH,
    APPROVALS_PATH,
    UNTRUSTED_NOTICE,
    ApprovalReader,
    operator_routes,
)
from acp.approvals.record import (
    DEFAULT_TTL_SECONDS,
    MAX_DISPLAYED_ARGUMENT_BYTES,
    ApprovalRequest,
    State,
    canonical,
    fingerprint,
    new_token,
    request_for,
)
from acp.approvals.store import ApprovalStore, InMemoryApprovalStore

__all__ = [
    "APPROVALS_PATH",
    "APPROVAL_PATH",
    "DEFAULT_TTL_SECONDS",
    "MAX_DISPLAYED_ARGUMENT_BYTES",
    "UNTRUSTED_NOTICE",
    "ApprovalReader",
    "ApprovalRequest",
    "ApprovalStore",
    "Gate",
    "InMemoryApprovalStore",
    "Outcome",
    "Resolution",
    "State",
    "canonical",
    "fingerprint",
    "gate",
    "new_token",
    "operator_routes",
    "request_for",
    "resolve",
]
